<?php

namespace Laraditz\SecurityScanner\Checkers;

use Laraditz\SecurityScanner\Finding;

class MassAssignmentChecker extends BaseChecker
{
    public function check(string $path): array
    {
        $findings  = [];
        $modelsDir = $path . '/app/Models';
        $searchDir = is_dir($modelsDir) ? $modelsDir : (is_dir($path . '/app') ? $path . '/app' : $path);

        foreach ($this->phpFiles($searchDir) as $file) {
            $contents = $file->getContents();

            // Only check files that extend Model
            if (!preg_match('/extends\s+(Eloquent\\\\)?Model/', $contents)) {
                continue;
            }

            // Flag $guarded = []
            if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $contents)) {
                preg_match('/class\s+(\w+)/', $contents, $classMatch);
                $class = $classMatch[1] ?? 'Unknown';

                $findings[] = new Finding(
                    severity: 'HIGH',
                    checker: $this->checkerName(),
                    file: $file->getPathname(),
                    line: null,
                    message: "Model {$class} has \$guarded = [] — all attributes are mass assignable",
                    recommendation: 'Define $fillable with only the columns users should be able to set',
                );
            }

            // Flag models with neither $fillable nor $guarded
            $hasFillable = str_contains($contents, '$fillable');
            $hasGuarded  = str_contains($contents, '$guarded');

            if (!$hasFillable && !$hasGuarded) {
                preg_match('/class\s+(\w+)/', $contents, $classMatch);
                $class = $classMatch[1] ?? 'Unknown';

                $findings[] = new Finding(
                    severity: 'MEDIUM',
                    checker: $this->checkerName(),
                    file: $file->getPathname(),
                    line: null,
                    message: "Model {$class} defines neither \$fillable nor \$guarded",
                    recommendation: 'Add $fillable to explicitly list which attributes can be mass assigned',
                );
            }
        }

        return $findings;
    }
}
