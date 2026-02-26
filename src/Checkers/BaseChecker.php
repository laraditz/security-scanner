<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;
use Symfony\Component\Finder\Finder;

abstract class BaseChecker
{
    /**
     * Run the checker against the given Laravel app path.
     *
     * @return Finding[]
     */
    abstract public function check(string $path): array;

    /**
     * Get all PHP files under the given directory.
     *
     * @return \Symfony\Component\Finder\SplFileInfo[]
     */
    protected function phpFiles(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $finder = new Finder();
        $finder->files()->name('*.php')->in($directory)->sortByName();

        return iterator_to_array($finder, false);
    }

    /**
     * Get all Blade template files.
     *
     * @return \Symfony\Component\Finder\SplFileInfo[]
     */
    protected function bladeFiles(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $finder = new Finder();
        $finder->files()->name('*.blade.php')->in($directory)->sortByName();

        return iterator_to_array($finder, false);
    }

    /**
     * Get checker short name for Finding objects.
     */
    protected function checkerName(): string
    {
        return class_basename(static::class);
    }
}
