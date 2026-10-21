<?php
/**
 * Application classes used by profile.php.
 *
 * UserPreferences is the "safe" looking data holder serialized into the
 * cookie. Logger is a gadget class: it has no business being reachable
 * from user input, but because unserialize() is called on untrusted
 * data, an attacker can craft a serialized Logger object whose
 * destructor performs a dangerous action. This mirrors the shape of
 * real PHP deserialization RCE chains (POP gadget chains), without
 * reproducing a specific disclosed exploit.
 */

class UserPreferences
{
    public $theme = 'light';
    public $language = 'es';
}

/**
 * GADGET CLASS: its __destruct() is attacker-reachable via
 * unserialize() on untrusted input. In a real gadget chain this would
 * usually be a class already present in the app or a dependency
 * (logging, cache, template engine, etc.) rather than something this
 * obviously named — named explicitly here for lab clarity.
 */
class Logger
{
    public $logFile;
    public $logMessage;

    public function __destruct()
    {
        // VULNERABLE: writes attacker-controlled content to an
        // attacker-controlled path with no validation whatsoever.
        if ($this->logFile && $this->logMessage) {
            file_put_contents($this->logFile, $this->logMessage, FILE_APPEND);
        }
    }
}
