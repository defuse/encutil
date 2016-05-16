<?php

/*
 * EncUtil: A utility for encrypting and decrypting files and messages.
 *
 * This tool exists to document correct and safe usage of the
 * defuse/php-encryption library. It is a fully-functional utility for
 * encrypting and decrypting files based on either a secret password or keyfile.
 *
 * Usage:
 *
 *      Encrypting a file with a password:
 *          php encutil.php --encrypt --password plaintext.txt ciphertext.bin
 *
 *      Decrypting a file with a password:
 *          php encutil.php --decrypt --password ciphertext.bin plaintext.txt
 *
 *      Generating a keyfile:
 *          php encutil.php --genkey secret-key.txt
 *
 *      Encrypting a file with a keyfile:
 *          php encutil.php --encrypt --keyfile secret-key.txt plaintext.txt ciphertext.bin
 *
 *      Decrypting a file with a keyfile:
 *          php encutil.php --decrypt --keyfile secret-key.txt ciphertext.bin plaintext.txt
 */

require_once 'vendor/autoload.php';

use Defuse\Crypto\Exception as Ex;
use Defuse\Crypto\File;
use Defuse\Crypto\Key;
use Defuse\Crypto\KeyProtectedByPassword;

class Prompt
{
    public static function PromptForPasswordAndVerify()
    {
        echo "Password: ";
        $pass1 = Seld\CliPrompt\CliPrompt::hiddenPrompt();
        echo "Enter it again: ";
        $pass2 = Seld\CliPrompt\CliPrompt::hiddenPrompt();
        while ($pass1 !== $pass2) {
            echo "The passwords didn't match. Try again.";
            echo "Password: ";
            $pass1 = Seld\CliPrompt\CliPrompt::hiddenPrompt();
            echo "Enter it again: ";
            $pass2 = Seld\CliPrompt\CliPrompt::hiddenPrompt();
        }
        return $pass1;
    }

    public static function PromptForPassword()
    {
        echo "Password: ";
        return Seld\CliPrompt\CliPrompt::hiddenPrompt();
    }

    public static function PromptYesNo($question)
    {
        echo $question . " [y/n]? ";
        $response = \Seld\CliPrompt\CliPrompt::prompt();
        while ($response !== "y" && $response !== "n") {
            echo "Please answer 'y' or 'n'.\n";
            echo $question . " [y/n]? ";
            $response = \Seld\CliPrompt\CliPrompt::prompt();
        }
        return $response === "y";
    }
}

interface iUseCase
{
    public static function MatchesPattern($argv);
    public function run();
}

class UseCaseEncryptFileWithPassword implements iUseCase
{
    private $input_path = null;
    private $output_path = null;

    public static function MatchesPattern($argv)
    {
        return count($argv) == 5 && 
               $argv[1] == "--encrypt" &&
               $argv[2] == "--password";
    }

    function __construct($argv)
    {
        if (!self::MatchesPattern($argv)) {
            throw new Exception("Use case pattern doesn't match.");
        }

        $this->input_path = $argv[3];
        $this->output_path = $argv[4];
    }

    function run()
    {
        $password = Prompt::PromptForPasswordAndVerify();
        try {
            File::encryptFileWithPassword($this->input_path, $this->output_path, $password);
        } catch (Ex\IOException $ex) {
            // TODO: But that's not what this exception means!
            echo <<<MSG
There was a file I/O error.

MSG;
            return false;
        }
        return true;
    }
}

class UseCaseDecryptFileWithPassword implements iUseCase
{
    private $input_path = null;
    private $output_path = null;

    public static function MatchesPattern($argv)
    {
        return count($argv) == 5 && 
               $argv[1] == "--decrypt" &&
               $argv[2] == "--password";
    }

    function __construct($argv)
    {
        if (!self::MatchesPattern($argv)) {
            throw new Exception("Use case pattern doesn't match.");
        }

        $this->input_path = $argv[3];
        $this->output_path = $argv[4];
    }

    function run()
    {
        $password = Prompt::PromptForPassword();
        try {
            File::decryptFileWithPassword($this->input_path, $this->output_path, $password);
        } catch (Ex\WrongKeyOrModifiedCiphertextException $ex) {
            echo <<<MSG
Either you're trying to decrypt with the wrong password, or the encrypted file
has been changed since it was first created. The changes might have been made by
someone trying to attack your security, so we will not proceed decrypting the
file.

MSG;
            return false;
        } catch (Ex\IOException $ex) {
            // TODO: But that's not what this exception means!
            echo <<<MSG
There was a file I/O error.

MSG;
            return false;
        }

        return true;
    }
}

class UseCaseGenerateKeyfile implements iUseCase
{
    private $path = null;

    public static function MatchesPattern($argv)
    {
        return count($argv) == 3 &&
            $argv[1] == "--genkey";
    }

    function __construct($argv)
    {
        if (!self::MatchesPattern($argv)) {
            throw new Exception("Use case pattern doesn't match.");
        }

        $this->path = $argv[2];
    }

    function run()
    {
        /* Generate a random key, optionally protected by a password. */
        $protect = Prompt::PromptYesNo("Would you like to protect your keyfile with a password?");
        if ($protect) {
            $password = Prompt::PromptForPasswordAndVerify();
            $protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey($password);
            $encoded_key = $protected_key->saveToAsciiSafeString();
        } else {
            $key = Key::createNewRandomKey();
            $encoded_key = $key->saveToAsciiSafeString();
        }

        /* Save the key to a file. */
        $ret = @file_put_contents($this->path, $encoded_key);
        if ($ret === false) {
            echo <<<MSG
There was an error writing to the file path you provided.

MSG;
            return false;
        }
        return true;
    }
}

class UseCaseEncryptFileWithKeyfile implements iUseCase
{
    private $input_path = null;
    private $output_path = null;
    private $keyfile_path = null;

    public static function MatchesPattern($argv)
    {
        return count($argv) == 6 &&
            $argv[1] == "--encrypt" &&
            $argv[2] == "--keyfile";
    }

    function __construct($argv)
    {
        if (!self::MatchesPattern($argv)) {
            throw new Exception("Use case pattern doesn't match.");
        }

        $this->keyfile_path = $argv[3];
        $this->input_path = $argv[4];
        $this->output_path = $argv[5];
    }

    function run()
    {
        $keyfile = @file_get_contents($this->keyfile_path);

        if ($keyfile === false) {
            echo <<<MSG
There was an error reading the keyfile you provided.

MSG;
            return false;
        }

        try {
            $key = Key::loadFromAsciiSafeString($keyfile);

        } catch (Ex\BadFormatException $ex) {
            $protected_key = KeyProtectedByPassword::loadFromAsciiSafeString($keyfile);
            $password = Prompt::PromptForPassword();
            try {
                $key = $protected_key->unlockKey($password);
            } catch (Ex\WrongKeyOrModifiedCiphertextException $ex) {
                echo <<<MSG
You've given the wrong password, or your keyfile is corrupted.

MSG;
                return false;
            }
        }

        try {
            File::encryptFile($this->input_path, $this->output_path, $key);
        } catch (Ex\IOException $ex) {
            // TODO: But that's not what this exception means!
            echo <<<MSG
There was a file I/O error.

MSG;
            return false;
        }

        return true;
    }
}

class UseCaseDecryptFileWithKeyfile implements iUseCase
{
    private $input_path = null;
    private $output_path = null;
    private $keyfile_path = null;

    public static function MatchesPattern($argv)
    {
        return count($argv) == 6 &&
            $argv[1] == "--decrypt" &&
            $argv[2] == "--keyfile";
    }

    function __construct($argv)
    {
        if (!self::MatchesPattern($argv)) {
            throw new Exception("Use case pattern doesn't match.");
        }

        $this->keyfile_path = $argv[3];
        $this->input_path = $argv[4];
        $this->output_path = $argv[5];
    }

    function run()
    {
        $keyfile = @file_get_contents($this->keyfile_path);

        if ($keyfile === FALSE) {
            echo <<<MSG
There was an error reading the keyfile you provided.

MSG;
            return false;
        }

        try {
            $key = Key::loadFromAsciiSafeString($keyfile);

        } catch (Ex\BadFormatException $ex) {
            $protected_key = KeyProtectedByPassword::loadFromAsciiSafeString($keyfile);
            $password = Prompt::PromptForPassword();
            try {
                $key = $protected_key->unlockKey($password);
            } catch (Ex\WrongKeyOrModifiedCiphertextException $ex) {
                echo <<<MSG
You've given the wrong password, or your keyfile is corrupted.

MSG;
                return false;
            }
        }

        try {
            File::decryptFile($this->input_path, $this->output_path, $key);
        } catch (Ex\WrongKeyOrModifiedCiphertextException $ex) {
            echo <<<MSG
Either you're trying to decrypt with the wrong keyfile, or the encrypted file
has been changed since it was first created. The changes might have been made by
someone trying to attack your security, so we will not proceed decrypting the
file.

MSG;
            return false;
        } catch (Ex\IOException $ex) {
            // TODO: But that's not what this exception means!
            echo <<<MSG
There was a file I/O error.

MSG;
            return false;
        }

        return true;
    }

}

if (UseCaseEncryptFileWithPassword::MatchesPattern($argv)) {
    $usecase = new UseCaseEncryptFileWithPassword($argv);
} else if (UseCaseDecryptFileWithPassword::MatchesPattern($argv)) {
    $usecase = new UseCaseDecryptFileWithPassword($argv);
} else if (UseCaseGenerateKeyfile::MatchesPattern($argv)) {
    $usecase = new UseCaseGenerateKeyfile($argv);
} else if (UseCaseEncryptFileWithKeyfile::MatchesPattern($argv)) {
    $usecase = new UseCaseEncryptFileWithKeyfile($argv);
} else if (UseCaseDecryptFileWithKeyfile::MatchesPattern($argv)) {
    $usecase = new UseCaseDecryptFileWithKeyfile($argv);
} else {
    echo "Bad command-line arguments.\n";
    exit(1);
}

$success = $usecase->run();
exit($success ? 0 : 1);
