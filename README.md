Dieses Repository erklärt, wie man ein sicheres Login-System mit PHP und MySQL implementieren könnte.

### 1. **Datenbankstruktur**
   - Eine Tabelle `users` wird mit den Feldern `id`, `email`, `passwort`, `vorname`, `nachname`, `created_at` und `updated_at` erstellt.
   - Passwörter werden mit `password_hash()` sicher verschlüsselt und in der Datenbank gespeichert.

### 2. **Registrierung**
   - In `registrieren.php` wird ein Formular zur Nutzerregistrierung bereitgestellt.
   - Das Formular überprüft die E-Mail-Adresse auf Gültigkeit und ob die Passwörter übereinstimmen.
   - Bei erfolgreicher Registrierung wird das Passwort gehasht und der Nutzer in die Datenbank eingefügt.

### 3. **Login**
   - In `login.php` wird das Login-Formular erstellt, das die E-Mail-Adresse und das Passwort des Nutzers prüft.
   - Wenn die Daten korrekt sind, wird die Session mit der Benutzer-ID gestartet.
   - Die Funktion `password_verify()` prüft, ob das eingegebene Passwort mit dem gespeicherten gehashten Passwort übereinstimmt.

### 4. **Geschützter Bereich**
   - In `geheim.php` wird geprüft, ob die Session-Variable `userid` gesetzt ist. Wenn nicht, wird der Nutzer aufgefordert, sich einzuloggen.

### 5. **Logout**
   - In `logout.php` wird die Session zerstört, um den Nutzer abzumelden.

Die grundlegenden Schritte umfassen also:
- Registrierung (mit Passwort-Hashing)
- Login (mit Passwort-Verifikation)
- Geschützten Bereich (nur zugänglich für eingeloggte Nutzer)
- Logout (Session beenden)

Hier sind die entsprechenden Quelltexte für das Login-, Registrierung-, geschützte Bereich- und Logout-System:

### 1. **Datenbankstruktur (MySQL)**
   Erstelle eine `users` Tabelle mit folgendem SQL-Code:
   ```sql
   CREATE TABLE `users` (
     `id` INT NOT NULL AUTO_INCREMENT,
     `email` VARCHAR(255) NOT NULL,
     `passwort` VARCHAR(255) NOT NULL,
     `vorname` VARCHAR(255) NOT NULL DEFAULT '',
     `nachname` VARCHAR(255) NOT NULL DEFAULT '',
     `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     `updated_at` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
     PRIMARY KEY (`id`), UNIQUE (`email`)
   ) ENGINE = InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
   ```

### 2. **Registrierung (registrieren.php)**
```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'root', '');

$showFormular = true;

if(isset($_GET['register'])) {
    $error = false;
    $email = $_POST['email'];
    $passwort = $_POST['passwort'];
    $passwort2 = $_POST['passwort2'];

    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo 'Bitte eine gültige E-Mail-Adresse eingeben<br>';
        $error = true;
    }
    if(strlen($passwort) == 0) {
        echo 'Bitte ein Passwort angeben<br>';
        $error = true;
    }
    if($passwort != $passwort2) {
        echo 'Die Passwörter müssen übereinstimmen<br>';
        $error = true;
    }

    // Überprüfe, ob E-Mail bereits existiert
    if(!$error) {
        $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
        $statement->execute(array('email' => $email));
        $user = $statement->fetch();

        if($user !== false) {
            echo 'Diese E-Mail-Adresse ist bereits vergeben<br>';
            $error = true;
        }
    }

    // Keine Fehler, registriere den Nutzer
    if(!$error) {
        $passwort_hash = password_hash($passwort, PASSWORD_DEFAULT);

        $statement = $pdo->prepare("INSERT INTO users (email, passwort) VALUES (:email, :passwort)");
        $result = $statement->execute(array('email' => $email, 'passwort' => $passwort_hash));

        if($result) {
            echo 'Du wurdest erfolgreich registriert. <a href="login.php">Zum Login</a>';
            $showFormular = false;
        } else {
            echo 'Beim Abspeichern ist ein Fehler aufgetreten<br>';
        }
    }
}

if($showFormular) {
?>
    <form action="?register=1" method="post">
        E-Mail:<br>
        <input type="email" size="40" maxlength="250" name="email"><br><br>

        Dein Passwort:<br>
        <input type="password" size="40" maxlength="250" name="passwort"><br>

        Passwort wiederholen:<br>
        <input type="password" size="40" maxlength="250" name="passwort2"><br><br>

        <input type="submit" value="Abschicken">
    </form>
<?php } ?>
```

### 3. **Login (login.php)**
```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'root', '');

if(isset($_GET['login'])) {
    $email = $_POST['email'];
    $passwort = $_POST['passwort'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $statement->execute(array('email' => $email));
    $user = $statement->fetch();

    // Überprüfe das Passwort
    if ($user !== false && password_verify($passwort, $user['passwort'])) {
        $_SESSION['userid'] = $user['id'];
        die('Login erfolgreich. Weiter zu <a href="geheim.php">internen Bereich</a>');
    } else {
        $errorMessage = "E-Mail oder Passwort war ungültig<br>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>

<?php if(isset($errorMessage)) { echo $errorMessage; } ?>

<form action="?login=1" method="post">
    E-Mail:<br>
    <input type="email" size="40" maxlength="250" name="email"><br><br>

    Dein Passwort:<br>
    <input type="password" size="40" maxlength="250" name="passwort"><br>

    <input type="submit" value="Abschicken">
</form>
</body>
</html>
```

### 4. **Geschützter Bereich (geheim.php)**
```php
<?php
session_start();
if(!isset($_SESSION['userid'])) {
    die('Bitte zuerst <a href="login.php">einloggen</a>');
}

$userid = $_SESSION['userid'];
echo "Hallo User: ".$userid;
?>
```

### 5. **Logout (logout.php)**
```php
<?php
session_start();
session_destroy();

echo "Logout erfolgreich";
?>
```

# Erweiterung um Passwort vergessen Option

Um die **Passwort vergessen**-Funktion in unser bestehendes Login-System zu integrieren, erweitern wir die Datenbank und fügen zwei neue PHP-Dateien hinzu: **passwortvergessen.php** und **passwortzuruecksetzen.php**. Hier sind die detaillierten Schritte und Quellcodes für die Erweiterung:

### 1. **Datenbankerweiterung**
Wir müssen die `users`-Tabelle um zwei Spalten erweitern: **`passwortcode`** und **`passwortcode_time`**. Dies ermöglicht es uns, einen temporären Code zu speichern, den der Benutzer verwenden kann, um sein Passwort zurückzusetzen.

```sql
ALTER TABLE `users` ADD `passwortcode` VARCHAR(255) NULL;
ALTER TABLE `users` ADD `passwortcode_time` TIMESTAMP NULL;
```

- **`passwortcode`** speichert den geheimen Code, der zum Zurücksetzen des Passworts benötigt wird.
- **`passwortcode_time`** speichert den Zeitpunkt, wann der Code generiert wurde. Nur Codes, die innerhalb der letzten 24 Stunden erstellt wurden, sind gültig.

### 2. **Passwort vergessen Seite (passwortvergessen.php)**

Diese Seite ermöglicht es einem Benutzer, seine E-Mail-Adresse einzugeben, um einen Link zum Zurücksetzen des Passworts zu erhalten. Der Link enthält den Benutzer-ID und einen zufällig generierten Code.

```php
<?php 
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');
 
// Zufälligen String für den Passwortcode generieren
function random_string() {
    if(function_exists('random_bytes')) {
        $bytes = random_bytes(16);
        $str = bin2hex($bytes); 
    } else if(function_exists('openssl_random_pseudo_bytes')) {
        $bytes = openssl_random_pseudo_bytes(16);
        $str = bin2hex($bytes); 
    } else if(function_exists('mcrypt_create_iv')) {
        $bytes = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
        $str = bin2hex($bytes); 
    } else {
        // Ein zufälliger String
        $str = md5(uniqid('euer_geheimer_string', true));
    }   
    return $str;
}

$showForm = true;

if(isset($_GET['send'])) {
    if(empty($_POST['email'])) {
        $error = "<b>Bitte eine E-Mail-Adresse eintragen</b>";
    } else {
        // Überprüfe, ob die E-Mail existiert
        $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
        $statement->execute(['email' => $_POST['email']]);
        $user = $statement->fetch();
 
        if($user === false) {
            $error = "<b>Kein Benutzer gefunden</b>";
        } else {
            // Generiere den Code
            $passwortcode = random_string();
            $statement = $pdo->prepare("UPDATE users SET passwortcode = :passwortcode, passwortcode_time = NOW() WHERE id = :userid");
            $statement->execute(['passwortcode' => sha1($passwortcode), 'userid' => $user['id']]);
 
            // Sende den Link mit dem Code per E-Mail
            $empfaenger = $user['email'];
            $betreff = "Neues Passwort für deinen Account";
            $from = "From: DeinName <absender@domain.de>";
            $url_passwortcode = 'http://localhost/passwortzuruecksetzen.php?userid='.$user['id'].'&code='.$passwortcode;
            $text = 'Hallo '.$user['vorname'].',
            
            Um dein Passwort zurückzusetzen, klicke bitte auf folgenden Link (gilt für 24 Stunden):
            '.$url_passwortcode.'
 
            Falls du diese Anfrage nicht gestellt hast, ignoriere bitte diese E-Mail.';
             
            mail($empfaenger, $betreff, $text, $from);
 
            echo "Ein Link zum Zurücksetzen des Passworts wurde an deine E-Mail-Adresse gesendet.";
            $showForm = false;
        }
    }
}

if($showForm):
?>

<h1>Passwort vergessen</h1>
Bitte gib deine E-Mail-Adresse ein, um ein neues Passwort anzufordern.<br><br>

<?php
if(isset($error)) {
    echo $error;
}
?>

<form action="?send=1" method="post">
E-Mail:<br>
<input type="email" name="email" value="<?php echo isset($_POST['email']) ? htmlentities($_POST['email']) : ''; ?>"><br>
<input type="submit" value="Neues Passwort anfordern">
</form>

<?php
endif; // End if($showForm)
?>
```

### 3. **Neues Passwort vergeben Seite (passwortzuruecksetzen.php)**

Wenn der Benutzer den Link in der E-Mail anklickt, wird er zu dieser Seite weitergeleitet, auf der er ein neues Passwort eingeben kann. Der Code wird überprüft, um sicherzustellen, dass er korrekt und noch gültig ist.

```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

if(!isset($_GET['userid']) || !isset($_GET['code'])) {
    die("Es wurde kein Code zum Zurücksetzen des Passworts übermittelt.");
}

$userid = $_GET['userid'];
$code = $_GET['code'];

// Überprüfe, ob der Benutzer existiert und der Code gültig ist
$statement = $pdo->prepare("SELECT * FROM users WHERE id = :userid");
$statement->execute(['userid' => $userid]);
$user = $statement->fetch();

if($user === null || $user['passwortcode'] === null) {
    die("Kein Benutzer mit diesem Code gefunden.");
}

if($user['passwortcode_time'] === null || strtotime($user['passwortcode_time']) < (time() - 24 * 3600)) {
    die("Dein Code ist leider abgelaufen.");
}

if(sha1($code) != $user['passwortcode']) {
    die("Der Code ist ungültig.");
}

// Der Code ist korrekt, der Benutzer kann ein neues Passwort eingeben
if(isset($_GET['send'])) {
    $passwort = $_POST['passwort'];
    $passwort2 = $_POST['passwort2'];
    
    if($passwort != $passwort2) {
        echo "Die Passwörter stimmen nicht überein.";
    } else {
        // Speichere das neue Passwort
        $passworthash = password_hash($passwort, PASSWORD_DEFAULT);
        $statement = $pdo->prepare("UPDATE users SET passwort = :passworthash, passwortcode = NULL, passwortcode_time = NULL WHERE id = :userid");
        $statement->execute(['passworthash' => $passworthash, 'userid' => $userid]);
        
        echo "Dein Passwort wurde erfolgreich geändert.";
    }
}
?>

<h1>Neues Passwort vergeben</h1>
<form action="?send=1&amp;userid=<?php echo htmlentities($userid); ?>&amp;code=<?php echo htmlentities($code); ?>" method="post">
    Neues Passwort:<br>
    <input type="password" name="passwort"><br><br>
 
    Passwort erneut eingeben:<br>
    <input type="password" name="passwort2"><br><br>
 
    <input type="submit" value="Passwort speichern">
</form>
```

### 4. **Erklärung der Funktionalität**

- **Passwort vergessen (passwortvergessen.php):**
  - Der Benutzer gibt seine E-Mail-Adresse ein. Wenn der Benutzer existiert, wird ein zufälliger Code generiert und in der Datenbank gespeichert.
  - Eine E-Mail mit einem Link wird an den Benutzer gesendet. Dieser Link enthält den Benutzer-ID und den generierten Code.
  
- **Neues Passwort vergeben (passwortzuruecksetzen.php):**
  - Der Benutzer klickt auf den Link in der E-Mail und wird zur Seite weitergeleitet.
  - Der Code und die Benutzer-ID aus der URL werden überprüft. Wenn alles stimmt und der Code noch gültig ist, kann der Benutzer ein neues Passwort eingeben.
  - Das neue Passwort wird gehasht und in der Datenbank gespeichert. Der temporäre Code wird gelöscht.

Mit dieser Erweiterung kann ein Benutzer sein Passwort zurücksetzen, falls er es vergessen hat, ohne dass das Passwort direkt per E-Mail versendet wird.

# Erweiterung um Angemeldet bleiben Funktion

Um die **"Angemeldet bleiben"**-Funktion hinzuzufügen, erweitern wir das Login-System so, dass Benutzer auch nach dem Schließen ihres Browsers weiterhin angemeldet bleiben. Dazu nutzen wir **Cookies**, die eine längere Sitzung ermöglichen. Bei einem erfolgreichen Login werden zusätzlich **Cookies** gesetzt, die die Benutzer-ID und ein Verifizierungstoken speichern. Diese Tokens werden bei jeder Anfrage überprüft, um zu verifizieren, dass der Benutzer authentifiziert ist.

Hier ist, wie wir das bestehende System erweitern können:

### 1. **Datenbankänderung: Zusätzliche Spalte für das Token**

Zuerst fügen wir der **`users`-Tabelle** ein Feld hinzu, um das **Token** für die "Angemeldet bleiben"-Funktion zu speichern.

#### SQL zum Hinzufügen der `remember_token`-Spalte:
```sql
ALTER TABLE users ADD COLUMN remember_token VARCHAR(255) NULL;
```

- **`remember_token`**: Hier wird das Token gespeichert, das der Benutzer in einem Cookie erhält, um die Sitzung zu authentifizieren.

---

### 2. **Login-Formular anpassen: Token setzen**

Nun passen wir das Login-Skript so an, dass es beim erfolgreichen Login zusätzlich ein **Token** generiert und als **Cookie** setzt, wenn der Benutzer die "Angemeldet bleiben"-Option auswählt.

#### Quellcode für `login.php` mit "Angemeldet bleiben"-Funktion:

```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

// Wenn das Formular abgesendet wird
if (isset($_POST['submit'])) {
    $email = $_POST['email'];
    $passwort = $_POST['passwort'];
    $remember = isset($_POST['remember']) ? true : false;  // Überprüfe, ob "Angemeldet bleiben" ausgewählt wurde

    // Benutzerdaten aus der Datenbank holen
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if ($user && password_verify($passwort, $user['passwort'])) {
        // Login erfolgreich, Benutzer-ID in Session speichern
        $_SESSION['user_id'] = $user['id'];

        // "Angemeldet bleiben"-Funktion: Token generieren
        if ($remember) {
            // Ein zufälliges Token generieren
            $token = bin2hex(random_bytes(16));

            // Token in der Datenbank speichern
            $stmt = $pdo->prepare("UPDATE users SET remember_token = :token WHERE id = :id");
            $stmt->execute(['token' => $token, 'id' => $user['id']]);

            // Cookie setzen (gültig für 30 Tage)
            setcookie('remember_token', $token, time() + (30 * 24 * 60 * 60), '/', null, null, true); // HttpOnly und Secure setzen, wenn auf HTTPS
        }

        echo "Login erfolgreich!";
        header("Location: dashboard.php");
        exit();
    } else {
        echo "Ungültige E-Mail oder Passwort!";
    }
}
?>

<form method="post" action="">
    E-Mail: <input type="email" name="email" required><br>
    Passwort: <input type="password" name="passwort" required><br>
    <input type="checkbox" name="remember"> Angemeldet bleiben<br>
    <input type="submit" name="submit" value="Login">
</form>
```

**Erklärung**:
- Wenn der Benutzer die "Angemeldet bleiben"-Option auswählt, wird ein **Token** generiert, in der Datenbank gespeichert und als **Cookie** auf dem Client gesetzt.
- Das Cookie wird 30 Tage lang gespeichert, sodass der Benutzer auch nach dem Schließen des Browsers weiterhin eingeloggt bleibt.

---

### 3. **Token bei jedem Aufruf überprüfen: Automatisches Anmelden**

Nun müssen wir sicherstellen, dass bei jeder Anfrage überprüft wird, ob ein gültiges **Remember-Token** vorhanden ist. Wenn ja, authentifizieren wir den Benutzer automatisch.

#### Quellcode für `check_login.php` (Überprüfung des Tokens bei jeder Anfrage):

```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

// Wenn der Benutzer bereits eingeloggt ist
if (isset($_SESSION['user_id'])) {
    // Benutzer ist bereits angemeldet, keine weiteren Aktionen erforderlich
    return;
}

// Wenn kein Benutzer in der Session ist, überprüfen wir das Token im Cookie
if (isset($_COOKIE['remember_token'])) {
    $token = $_COOKIE['remember_token'];

    // Benutzer mit diesem Token finden
    $stmt = $pdo->prepare("SELECT * FROM users WHERE remember_token = :token");
    $stmt->execute(['token' => $token]);
    $user = $stmt->fetch();

    if ($user) {
        // Benutzer ist authentifiziert, setzen wir die Session
        $_SESSION['user_id'] = $user['id'];

        // Optional: Token erneuern (für längere Gültigkeit)
        $new_token = bin2hex(random_bytes(16));
        $stmt = $pdo->prepare("UPDATE users SET remember_token = :token WHERE id = :id");
        $stmt->execute(['token' => $new_token, 'id' => $user['id']]);

        // Neues Token im Cookie setzen
        setcookie('remember_token', $new_token, time() + (30 * 24 * 60 * 60), '/', null, null, true); // HttpOnly und Secure setzen
    }
}
?>
```

**Erklärung**:
- Wenn der Benutzer bereits in der Session ist, passiert nichts. Wenn jedoch kein Benutzer in der Session eingeloggt ist, prüfen wir, ob ein **Token** im **Cookie** existiert.
- Wenn das Token gültig ist, wird der Benutzer automatisch eingeloggt, und die Session wird entsprechend gesetzt.
- Der **Token** wird auch erneuert, damit der Benutzer für weitere 30 Tage angemeldet bleibt.

---

### 4. **Logout-Logik mit "Angemeldet bleiben"**

Wenn der Benutzer sich ausloggt, müssen wir das Token im Cookie und der Datenbank entfernen, um sicherzustellen, dass der Benutzer nicht mehr automatisch eingeloggt wird.

#### Quellcode für `logout.php` (inklusive "Angemeldet bleiben"):

```php
<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

// Token in der Datenbank auf NULL setzen
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("UPDATE users SET remember_token = NULL WHERE id = :id");
    $stmt->execute(['id' => $_SESSION['user_id']]);

    // Session und Cookie löschen
    setcookie('remember_token', '', time() - 3600, '/', null, null, true);  // Cookie löschen
    session_unset();
    session_destroy();

    echo "Du wurdest erfolgreich ausgeloggt!";
    header("Location: login.php");
    exit();
}
?>
```

**Erklärung**:
- Wenn der Benutzer sich ausloggt, wird das **Token** in der Datenbank auf `NULL` gesetzt und das **Cookie** gelöscht.
- Der Benutzer wird dann auf die Login-Seite weitergeleitet.

---

### Zusammenfassung

Mit dieser Erweiterung haben wir die **"Angemeldet bleiben"-Funktion** hinzugefügt. Wenn der Benutzer die entsprechende Option auswählt, wird ein **Token** generiert und im **Cookie** des Benutzers gespeichert. Bei jeder Anfrage wird überprüft, ob ein gültiges Token vorhanden ist, und der Benutzer wird automatisch angemeldet.

- **Token-Generierung**: Bei jedem Login wird ein einzigartiges Token erstellt und in der Datenbank sowie als Cookie gespeichert.
- **Token-Überprüfung**: Bei jedem Seitenaufruf wird das Token überprüft, um den Benutzer automatisch anzumelden.
- **Logout**: Beim Logout wird das Token entfernt, und der Benutzer wird von der Sitzung abgemeldet.

Diese Funktion sorgt für ein angenehmes Benutzererlebnis, da der Benutzer nicht jedes Mal seine Anmeldedaten eingeben muss, wenn er die Seite besucht.


