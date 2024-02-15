process.stdout.write('::debug::Hello Debug\n');

process.stdout.write('::group::The answer\n');
const answer = process.env['INPUT_ANSWER'];
process.stdout.write('::warning::The answer to life, the universe, and everything else is ' + answer + '.\n');
process.stdout.write('::endgroup::\n');

process.stdout.write('::notice::OK. Successfully ran a custom JS action :-)\n');
process.exit(0);
