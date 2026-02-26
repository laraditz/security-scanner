<?php
// tests/Fixtures/safe/mass_assignment.php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;

class SafeUser extends Model
{
    protected $fillable = ['name', 'email'];
}

class SafePost extends Model
{
    protected $guarded = ['id', 'admin'];
}
