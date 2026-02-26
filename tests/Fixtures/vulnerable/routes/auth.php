<?php
use Illuminate\Support\Facades\Route;
// VULNERABLE: no rate limiting on auth routes
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
