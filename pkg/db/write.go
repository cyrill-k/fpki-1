package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/netsec-ethz/fpki/pkg/common"
)

// UpdateDomainEntries: Update a list of key-value store
func (c *mysqlDB) UpdateDomainEntries(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error) {
	numOfUpdatedRecords, err := c.doUpdatePairs(ctx, keyValuePairs, c.getDomainEntriesUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateDomainEntries | %w", err)
	}
	return numOfUpdatedRecords, nil
}

// DeleteTreeNodes  deletes a list of key-value stored in the tree table.
func (c *mysqlDB) DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getTreeDeleteStmts)
	if err != nil {
		return 0, fmt.Errorf("DeleteTreeNodes | %w", err)
	}

	return n, nil
}

// UpdateTreeNodes: Update a list of key-value store
func (c *mysqlDB) UpdateTreeNodes(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error) {
	numOfUpdatedPairs, err := c.doUpdatePairs(ctx, keyValuePairs, c.getTreeStructureUpdateStmts)
	if err != nil {
		return 0, fmt.Errorf("UpdateTreeNodes | %w", err)
	}
	return numOfUpdatedPairs, nil
}

// AddUpdatedDomains inserts a list of keys into the updates table.
// If a key exists, ignores it.
func (c *mysqlDB) AddUpdatedDomains(ctx context.Context, keys []common.SHA256Output) (int, error) {
	n, err := c.doUpdateKeys(ctx, keys, c.getUpdatesInsertStmts)
	if err != nil {
		return 0, fmt.Errorf("AddUpdatedDomains | %w", err)
	}
	return n, nil
}

// RemoveAllUpdatedDomains: truncate updates table
func (c *mysqlDB) RemoveAllUpdatedDomains(ctx context.Context) error {
	_, err := c.db.Exec("TRUNCATE `fpki`.`updates`;")
	if err != nil {
		return fmt.Errorf("RemoveAllUpdatedDomains | TRUNCATE | %w", err)
	}
	return nil
}

// updateKeyValuesFcn
// stmtGen generates a new prepared statement, in case the size changes.
// parameters is reserved once with batchSize and passed along.
// keyValuePairs is the slice with all the key-values to insert, not only one batch.
// The function returns the number of rows affected, or error.
func updateKeyValuesFcn(stmtGen prepStmtGetter, parameters []interface{}, kvPairs []*KeyValuePair,
	stmt *sql.Stmt, first, last int) (int, error) {

	// Check if the size is too big for MySQL (max_allowed_packet must always be < 1G).
	size := 0
	for j := first; j <= last; j++ {
		size += len(kvPairs[j].Value)
	}
	if size > 1024*1024*1024 {
		// This is too big to be sent to MySQL, it will receive a
		//     "Error 1105: Parameter of prepared statement which is set through
		//      mysql_send_long_data() is longer than 'max_allowed_packet' bytes"
		// and fail. We need to split the data.
		fmt.Printf("Detected one case of gigantism: data is %d Mb. Splitting in two.\n",
			size/1024/1024)
		if first == last {
			panic(fmt.Errorf("cannot split: this is just one entry. Size=%d bytes, key=%s",
				size, hex.EncodeToString(kvPairs[first].Key[:])))
		}
		last1 := (last-first+1)/2 + first - 1
		// The size has changed, generate a new prepared statement.
		_, stmt := stmtGen(last1 - first + 1)
		n, err := updateKeyValuesFcn(stmtGen, parameters, kvPairs, stmt, first, last1)
		if err != nil {
			return n, err
		}
		_, stmt = stmtGen(last - (last1 + 1) + 1)
		n2, err := updateKeyValuesFcn(stmtGen, parameters, kvPairs, stmt, last1+1, last)
		return n2 + n, err
	}

	data := parameters[:2*(last-first+1)]
	for j := 0; j < len(data)/2; j++ {
		data[2*j] = kvPairs[first+j].Key[:]
		data[2*j+1] = kvPairs[first+j].Value
	}
	for {
		result, err := stmt.Exec(data...)
		if err != nil {
			if myerr, ok := err.(*mysql.MySQLError); ok && myerr.Number == 1213 { // deadlock
				// A deadlock was found, just cancel this operation and retry until success.
				continue
			}
			return 0, fmt.Errorf("updateFcn | Exec | %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("updateFcn | RowsAffected | %w", err)
		}
		return int(n), nil
	}
}

// ********************************************************************
//
//	Common
//
// ********************************************************************
// worker to update key-value pairs
func (c *mysqlDB) doUpdatePairs(ctx context.Context, keyValuePairs []*KeyValuePair,
	stmtGetter prepStmtGetter) (int, error) {

	dataLen := len(keyValuePairs)
	affectedRowsCount := 0

	data := make([]interface{}, 2*batchSize) // 2 elements per record
	updateWholeBatchStmt, updatePartialBatchStmt := stmtGetter(dataLen % batchSize)
	updateAdapter := func(stmt *sql.Stmt, first, last int) (int, error) {
		return updateKeyValuesFcn(stmtGetter, data, keyValuePairs, stmt, first, last)
	}

	for i := 0; i < dataLen/batchSize; i++ {
		n, err := updateAdapter(updateWholeBatchStmt, i*batchSize, (i+1)*batchSize-1)
		if err != nil {
			return 0, fmt.Errorf("doUpdatePairs | wholeBatch | %w", err)
		}
		affectedRowsCount += n
	}
	if dataLen%batchSize > 0 {
		n, err := updateAdapter(updatePartialBatchStmt, dataLen/batchSize*batchSize, dataLen-1)
		if err != nil {
			return 0, fmt.Errorf("doUpdatePairs | partialBatch | %w", err)
		}
		affectedRowsCount += n
	}
	//defer updateWholeBatchStmt.Close()
	//defer updatePartialBatchStmt.Close()
	return affectedRowsCount, nil
}

// worker to update keys
func (c *mysqlDB) doUpdateKeys(ctx context.Context, keys []common.SHA256Output,
	stmtGetter prepStmtGetter) (int, error) {

	dataLen := len(keys)
	affectedRowsCount := 0

	if dataLen == 0 {
		return 0, nil
	}

	data := make([]interface{}, batchSize)
	// updateFcn updates the DB using keys starting at index/batch, until the end of the
	// batch or the end of keyValuePairs
	updateFcn := func(stmt *sql.Stmt, index int) (int, error) {
		for {
			data := data[:min(batchSize, dataLen-batchSize*index)]
			for j := 0; j < len(data); j++ {
				data[j] = keys[index*batchSize+j][:]
			}
			result, err := stmt.Exec(data...)
			if err != nil {
				if myerr, ok := err.(*mysql.MySQLError); ok && myerr.Number == 1213 { // deadlock
					// A deadlock was found, just cancel this operation and retry until success.
					continue
				}
				return 0, fmt.Errorf("updateFcn | Exec | %w", err)
			}
			n, err := result.RowsAffected()
			if err != nil {
				return 0, fmt.Errorf("updateFcn | RowsAffected | %w", err)
			}
			return int(n), nil
		}
	}

	updateWholeBatchStmt, updatePartialBatchStmt := stmtGetter(dataLen % batchSize)
	for i := 0; i < dataLen/batchSize; i++ {
		n, err := updateFcn(updateWholeBatchStmt, i)
		if err != nil {
			return 0, fmt.Errorf("doUpdateKeys | wholeBatch | %w", err)
		}
		affectedRowsCount += n
	}
	if dataLen%batchSize > 0 {
		n, err := updateFcn(updatePartialBatchStmt, dataLen/batchSize)
		if err != nil {
			return 0, fmt.Errorf("doUpdateKeys | partialBatch | %w", err)
		}
		affectedRowsCount += n
	}
	return affectedRowsCount, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
