<div>
    {{ $userInput }}
    {{ $comment->body }}
    <p>{{ request('name') }}</p>
    {!! nl2br(e($userInput)) !!}
</div>
