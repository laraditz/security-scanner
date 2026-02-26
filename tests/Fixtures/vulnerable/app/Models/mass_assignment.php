<?php
// tests/Fixtures/vulnerable/mass_assignment.php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;

class VulnerableUser extends Model
{
    // VULNERABLE: empty guarded = everything is fillable
    protected $guarded = [];
}

class VulnerablePost extends Model
{
    // VULNERABLE: no $fillable and no $guarded defined
}
