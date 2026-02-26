<?php
// tests/Fixtures/safe/file_upload.php
class SafeUploadController
{
    public function store(Request $request)
    {
        $request->validate([
            'avatar' => 'required|file|mimes:jpg,png,gif|max:2048',
            'doc'    => 'required|file|mimetypes:application/pdf|max:10240',
        ]);

        // SAFE: random name, stored outside public/
        $path = $request->file('avatar')->store('avatars', 'private');
    }
}
