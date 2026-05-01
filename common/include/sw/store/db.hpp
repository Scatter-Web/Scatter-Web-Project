#pragma once
#include <sw/types.hpp>
#include <functional>
#include <optional>
#include <span>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace sw::store {

class DbError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// RAII row handle: wraps a sqlite3_stmt* that has been stepped once (SQLITE_ROW).
// Bind parameters are 1-indexed; columns are 0-indexed (matching SQLite convention).
class Row {
public:
    explicit Row(sqlite3_stmt* stmt) : stmt_(stmt) {}

    std::optional<int64_t>     get_int(int col)  const;
    std::optional<std::string> get_text(int col) const;
    std::optional<Bytes>       get_blob(int col) const;
    bool                       is_null(int col)  const;

    int64_t     require_int(int col)  const;
    std::string require_text(int col) const;
    Bytes       require_blob(int col) const;

private:
    sqlite3_stmt* stmt_;
};

// RAII prepared statement.
class Stmt {
public:
    Stmt() = default;
    explicit Stmt(sqlite3* db, std::string_view sql);
    ~Stmt();
    Stmt(Stmt&&) noexcept;
    Stmt& operator=(Stmt&&) noexcept;
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    // Bind by 1-based index
    Stmt& bind_int(int idx, int64_t v);
    Stmt& bind_text(int idx, std::string_view v);
    Stmt& bind_blob(int idx, ByteSpan v);
    Stmt& bind_null(int idx);

    // Execute without returning rows (INSERT/UPDATE/DELETE). Resets after.
    void exec();

    // Execute and call cb for every row. Resets after.
    void query(const std::function<void(const Row&)>& cb);

    // Execute and call cb for the first row only. Returns true if a row existed.
    // Row is only valid within the callback — do not store Row references.
    bool query_one(const std::function<void(const Row&)>& cb);

    // Reset bindings and step counter for reuse.
    void reset();

private:
    sqlite3_stmt* stmt_ = nullptr;
};

// RAII database connection with WAL mode and helpers.
class Db {
public:
    explicit Db(std::string_view path);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    // Prepare a statement (cached by the caller for reuse).
    Stmt prepare(std::string_view sql);

    // Execute raw SQL (for DDL / multi-statement setup).
    void exec(std::string_view sql);

    // Transaction helpers.
    void begin();
    void commit();
    void rollback();

    // RAII transaction guard.
    struct Txn {
        explicit Txn(Db& db) : db_(db) { db_.begin(); }
        ~Txn() { if (!done_) db_.rollback(); }
        void commit() { db_.commit(); done_ = true; }
    private:
        Db&  db_;
        bool done_ = false;
    };
    Txn transaction() { return Txn(*this); }

    int64_t last_insert_rowid() const;

    sqlite3* handle() { return db_; }

private:
    sqlite3* db_ = nullptr;
};

} // namespace sw::store
