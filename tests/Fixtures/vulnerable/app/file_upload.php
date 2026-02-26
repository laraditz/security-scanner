<?php
// tests/Fixtures/vulnerable/file_upload.php
class UploadController
{
    public function store(Request $request)
    {
        // VULNERABLE: uses original filename (path traversal risk)
        $name = $request->file('avatar')->getClientOriginalName();
        $request->file('avatar')->move(public_path('uploads'), $name);

        // VULNERABLE: only checks extension, not MIME type
        $ext = $request->file('doc')->getClientOriginalExtension();
        if (in_array($ext, ['pdf', 'doc'])) {
            $request->file('doc')->storeAs('public/docs', $name);
        }
    }
}
