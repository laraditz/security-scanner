<?php
// tests/Fixtures/vulnerable/sql_injection.php
use Illuminate\Support\Facades\DB;

class UserRepository
{
    public function findByName(string $name)
    {
        // VULNERABLE: string concatenation in raw query
        return DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
    }

    public function search(string $term)
    {
        // VULNERABLE: variable interpolation
        return DB::statement("DELETE FROM logs WHERE message = '$term'");
    }

    public function getByStatus(string $status)
    {
        // VULNERABLE: whereRaw with concatenation
        return User::whereRaw("status = '" . $status . "'")->get();
    }

    public function unpreparedQuery()
    {
        // VULNERABLE: DB::unprepared is always risky
        return DB::unprepared("TRUNCATE TABLE cache");
    }
}
