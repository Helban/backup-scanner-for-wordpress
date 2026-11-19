<?php
// Records PHP's own version_compare() for every pair of the versions below, so the scanner's
// JavaScript copy of it can be tested against the original. wpvulnerability.net states its
// version ranges in version_compare() terms, and its own WordPress plugin compares with it.
//
// Run from the repo root (writes version_compare.json next to this file):
// docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/tests/reference:/r" php:8.4-cli php /r/version_compare.php

$versions = [
    '1', '1.0', '1.0.0', '1.0.0.0', '1.00', '01.0', '1.0.1', '1.1', '1.9', '1.10', '1.10.0', '2', '10',
    '1.0-dev', '1.0dev', '1.0-alpha', '1.0alpha1', '1.0a', '1.0a2', '1.0-beta', '1.0b1', '1.0-b2',
    '1.0RC1', '1.0rc1', '1.0-RC2', '1.0pl1', '1.0p1', '1.0-patch', '1.0.0-beta.2', '1.0+build5',
    '1.0_1', '1.0-1', '1..0', '1.0.', '.1', '1.0abc', '1.0xyz', '1.0x', 'abc', 'dev', 'pl',
    '2.6.3.1', '2.6.3.2', '4.6.9', '4.12.3', '4.12.4', '4.4.6.3', '3.25.1', '7.1.4', '6.8',
    '5.0-beta', '5.0', '5.0.0-rc.1', '20240101', '2024.01.01', '1.2.3.4.5.6',
];

$results = [];
foreach ($versions as $left) {
    $row = [];
    foreach ($versions as $right) {
        $row[] = version_compare($left, $right);
    }
    $results[] = $row;
}

$recorded = json_encode(['php' => PHP_VERSION, 'versions' => $versions, 'results' => $results]) . "\n";
file_put_contents(__DIR__ . '/version_compare.json', $recorded);
