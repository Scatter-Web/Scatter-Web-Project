#include <sw/store/db.hpp>
#include <stdexcept>
#include <string>

namespace sw::store {

namespace {

void check(int rc, sqlite3* db, const char* context) {
    if (rc != SQLITE_OK && rc != SQLITE_ROW && rc != SQLITE_DONE)
        throw DbError(std::string(context) + ": " + sqlite3_errmsg(db));
}

} // namespace

// ── Row ──────────────────────────────────────────────────────────────────────

bool Row::is_null(int col) const {
    return sqlite3_column_type(stmt_, col) == SQLITE_NULL;
}

std::optional<int64_t> Row::get_int(int col) const {
    if (is_null(col)) return std::nullopt;
    return sqlite3_column_int64(stmt_, col);
}

std::optional<std::string> Row::get_text(int col) const {
    if (is_null(col)) return std::nullopt;
    const char* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt_, col));
    return p ? std::string(p) : std::string{};
}

std::optional<Bytes> Row::get_blob(int col) const {
    if (is_null(col)) return std::nullopt;
    const void* p = sqlite3_column_blob(stmt_, col);
    int n         = sqlite3_column_bytes(stmt_, col);
    if (!p || n == 0) return Bytes{};
    return Bytes(static_cast<const uint8_t*>(p),
                 static_cast<const uint8_t*>(p) + n);
}

int64_t Row::require_int(int col) const {
    auto v = get_int(col);
    if (!v) throw DbError("NULL where int required (col " + std::to_string(col) + ")");
    return *v;
}

std::string Row::require_text(int col) const {
    auto v = get_text(col);
    if (!v) throw DbError("NULL where text required (col " + std::to_string(col) + ")");
    return *v;
}

Bytes Row::require_blob(int col) const {
    auto v = get_blob(col);
    if (!v) throw DbError("NULL where blob required (col " + std::to_string(col) + ")");
    return *v;
}

// ── Stmt ─────────────────────────────────────────────────────────────────────

Stmt::Stmt(sqlite3* db, std::string_view sql) {
    int rc = sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()),
                                &stmt_, nullptr);
    check(rc, db, "sqlite3_prepare_v2");
}

Stmt::~Stmt() {
    if (stmt_) sqlite3_finalize(stmt_);
}

Stmt::Stmt(Stmt&& o) noexcept : stmt_(o.stmt_) { o.stmt_ = nullptr; }
Stmt& Stmt::operator=(Stmt&& o) noexcept {
    if (this != &o) {
        if (stmt_) sqlite3_finalize(stmt_);
        stmt_ = o.stmt_;
        o.stmt_ = nullptr;
    }
    return *this;
}

Stmt& Stmt::bind_int(int idx, int64_t v) {
    sqlite3_bind_int64(stmt_, idx, v);
    return *this;
}

Stmt& Stmt::bind_text(int idx, std::string_view v) {
    sqlite3_bind_text(stmt_, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}

Stmt& Stmt::bind_blob(int idx, ByteSpan v) {
    sqlite3_bind_blob(stmt_, idx, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}

Stmt& Stmt::bind_null(int idx) {
    sqlite3_bind_null(stmt_, idx);
    return *this;
}

void Stmt::exec() {
    int rc = sqlite3_step(stmt_);
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw DbError("sqlite3_step failed: " + std::to_string(rc));
}

void Stmt::query(const std::function<void(const Row&)>& cb) {
    for (;;) {
        int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            sqlite3_reset(stmt_);
            throw DbError("sqlite3_step failed: " + std::to_string(rc));
        }
        cb(Row{stmt_});
    }
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
}

bool Stmt::query_one(const std::function<void(const Row&)>& cb) {
    int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_DONE) {
        sqlite3_reset(stmt_);
        sqlite3_clear_bindings(stmt_);
        return false;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_reset(stmt_);
        throw DbError("sqlite3_step failed: " + std::to_string(rc));
    }
    cb(Row{stmt_});  // Row is valid here; stmt is in SQLITE_ROW state
    while (sqlite3_step(stmt_) == SQLITE_ROW) {}  // drain remaining rows
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
    return true;
}

void Stmt::reset() {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
}

// ── Db ───────────────────────────────────────────────────────────────────────

Db::Db(std::string_view path) {
    int rc = sqlite3_open(path.data(), &db_);
    if (rc != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "sqlite3_open failed";
        if (db_) sqlite3_close(db_);
        throw DbError("open(" + std::string(path) + "): " + msg);
    }
    // WAL mode and sensible defaults.
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA synchronous=NORMAL");
}

Db::~Db() {
    if (db_) sqlite3_close(db_);
}

Stmt Db::prepare(std::string_view sql) {
    return Stmt(db_, sql);
}

void Db::exec(std::string_view sql) {
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql.data(), nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string msg = errmsg ? errmsg : "sqlite3_exec failed";
        sqlite3_free(errmsg);
        throw DbError(msg);
    }
}

void Db::begin()    { exec("BEGIN"); }
void Db::commit()   { exec("COMMIT"); }
void Db::rollback() { exec("ROLLBACK"); }

int64_t Db::last_insert_rowid() const {
    return sqlite3_last_insert_rowid(db_);
}

} // namespace sw::store
