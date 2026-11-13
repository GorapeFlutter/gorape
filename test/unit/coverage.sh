#!/bin/bash

# Script to check test coverage for all packages

set -e

echo "========================================="
echo "Running Unit Tests with Coverage"
echo "========================================="
echo ""

# Find all directories under test/unit/pkg that contain at least one _test.go file
test_dirs=$(find test/unit/pkg -type f -name '*_test.go' -print0 | xargs -0 -n1 dirname | sort -u)

# Convert the list of test directories to package names relative to pkg/
packages=()
for dir in $test_dirs; do
    # Remove the 'test/unit/pkg/' prefix
    pkg_name=${dir#test/unit/pkg/}
    packages+=("$pkg_name")
done

total_coverage=0
package_count=0

for pkg in "${packages[@]}"; do
    echo "Testing pkg/$pkg..."
    # Define test path and package path
    test_path="./test/unit/pkg/$pkg/..."
    cover_path="./pkg/$pkg/..."

    # Run test and capture coverage
    result=$(go test -cover -coverpkg=$cover_path $test_path 2>&1 | grep "coverage:" || echo "coverage: 0.0%")
    coverage=$(echo "$result" | grep -oE '[0-9]+\.[0-9]+%' | head -1)
    
    if [ -n "$coverage" ]; then
        echo "  ✓ Coverage: $coverage"
        # Extract numeric value for averaging
        numeric_coverage=$(echo "$coverage" | grep -oE '[0-9]+\.[0-9]+')
        total_coverage=$(echo "$total_coverage + $numeric_coverage" | bc)
        package_count=$((package_count + 1))
    else
        echo "  ✗ No coverage data"
    fi
    echo ""
done

echo "========================================="
echo "Summary"
echo "========================================="

if [ $package_count -gt 0 ]; then
    avg_coverage=$(echo "scale=1; $total_coverage / $package_count" | bc)
    echo "Packages tested: $package_count"
    echo "Average coverage: ${avg_coverage}%"
    
    if (( $(echo "$avg_coverage >= 100.0" | bc -l) )); then
        echo "Status: ✓ Target achieved! (100%)"
    elif (( $(echo "$avg_coverage >= 80.0" | bc -l) )); then
        echo "Status: ⚠ Good progress (>80%)"
    else
        echo "Status: ✗ Needs improvement (<80%)"
    fi
else
    echo "No packages with tests found"
fi

echo ""
echo "To generate detailed HTML coverage report:"
echo "  go test -coverpkg=./pkg/... ./test/unit/pkg/... -coverprofile=coverage.out && go tool cover -html=coverage.out -o coverage.html"
