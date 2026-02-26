<?php
// tests/Fixtures/vulnerable/routes_web.php
use Illuminate\Support\Facades\Route;

// VULNERABLE: no auth middleware
Route::get('/admin/users', [AdminController::class, 'index']);
Route::post('/admin/users/{id}/delete', [AdminController::class, 'destroy']);
Route::get('/profile/settings', [ProfileController::class, 'settings']);
