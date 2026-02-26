<?php
// tests/Fixtures/safe/routes_web.php
use Illuminate\Support\Facades\Route;

Route::middleware(['auth'])->group(function () {
    Route::get('/admin/users', [AdminController::class, 'index']);
    Route::get('/profile/settings', [ProfileController::class, 'settings']);
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::post('/admin/users/{id}/delete', [AdminController::class, 'destroy']);
});
