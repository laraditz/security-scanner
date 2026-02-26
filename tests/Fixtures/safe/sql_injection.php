<?php
// tests/Fixtures/safe/sql_injection.php
use Illuminate\Support\Facades\DB;

class SafeUserRepository
{
    public function findByName(string $name)
    {
        // SAFE: parameter binding
        return DB::select("SELECT * FROM users WHERE name = ?", [$name]);
    }

    public function search(string $term)
    {
        // SAFE: named binding
        return DB::select("SELECT * FROM logs WHERE message = :term", ['term' => $term]);
    }

    public function getByStatus(string $status)
    {
        // SAFE: Eloquent where
        return User::where('status', $status)->get();
    }
}
