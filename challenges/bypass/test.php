<?php
function sanitizeString($input) {
    $pattern = '/[\'"\(\)%=;\.\s-]/';
    $sanitized = preg_replace($pattern, '', $input);
    return $sanitized;
}

function removeBadStrings($input) {
    $badStrings = array(
        '/UNION/i',
        '/OR/i',
        '/AND/i',
        '/BY/i',
        '/SELECT/i',
        '/SLEEP/i',
        '/BENCHMARK/i',
        '/TRUE/i',
        '/FALSE/i',
        '/\d/'
    );
    $cleanedInput = preg_replace($badStrings, '', $input);
    return $cleanedInput;
}

function sanitizeImagePath($imagePath) {
    $blacklist = array("./", "\\");

    $sanitizedPath = str_replace($blacklist, "", $imagePath);

    if (strpos($sanitizedPath, "images/") !== 0) {
        $sanitizedPath = "assets/img/" . $sanitizedPath;
    } else {
        echo "Invalid path";
    }

    return $sanitizedPath;
}

echo sanitizeImagePath('...//...//...//...//etc/passwd');