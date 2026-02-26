<?php
// tests/Fixtures/safe/secrets.php
class ApiClient
{
    private $apiKey;

    public function __construct()
    {
        $this->apiKey = config('services.api.key');
    }
}
