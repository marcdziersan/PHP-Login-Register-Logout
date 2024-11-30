### Tutorial: Sichere Login-System mit PHP, MySQL und "Angemeldet bleiben" Funktion

Dieses Tutorial erklärt, wie man ein sicheres Login-System mit PHP und MySQL implementiert, das eine "Angemeldet bleiben"-Funktion enthält. Es umfasst die Registrierung von Nutzern, das Login, einen geschützten Bereich, das Logout sowie eine Erweiterung zur Passwort-Wiederherstellung. Am Ende zeigen wir, wie man ein "Angemeldet bleiben"-Feature hinzufügt.

---

### **1. Datenbankstruktur**

Zunächst erstellen wir eine `users`-Tabelle, die für das Speichern der Benutzerinformationen zuständig ist:

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

---

### **2. Registrierung (registrieren.php)**

In diesem Schritt erstellen wir das Formular für die Registrierung und validieren die Eingaben:

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

---

### **3. Login (login.php)**

Hier erstellen wir das Login-Formular, das die Benutzerdaten überprüft:

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

---

### **4. Geschützter Bereich (geheim.php)**

Hier schützen wir einen Bereich, der nur zugänglich ist, wenn der Benutzer eingeloggt ist:

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

---

### **5. Logout (logout.php)**

Im Logout-Skript wird die Session beendet, und der Benutzer wird abgemeldet:

```php
<?php
session_start();
session_destroy();

echo "Logout erfolgreich";
?>
```

---

### **Erweiterung: Passwort vergessen**

Für die Erweiterung der "Passwort vergessen"-Funktion erweitern wir die `users`-Tabelle und fügen zwei neue Seiten hinzu: `passwortvergessen.php` und `passwortzuruecksetzen.php`.

#### 1. **Datenbankerweiterung**:

Fügen Sie zwei Spalten hinzu, um das Passwort zurückzusetzen:

```sql
ALTER TABLE `users` ADD `passwortcode` VARCHAR(255) NULL;
ALTER TABLE `users` ADD `passwortcode_time` TIMESTAMP NULL;
```

#### 2. **Passwort vergessen Seite (passwortvergessen.php)**

Diese Seite ermöglicht es dem Benutzer, seine E-Mail-Adresse einzugeben, um einen Link zum Zurücksetzen des Passworts zu erhalten.

```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

function random_string() {
    $str = bin2hex(random_bytes(16));
    return $str;
}

$showForm = true;

if(isset($_GET['send'])) {
    if(empty($_POST['email'])) {
        $error = "<b>Bitte eine E-Mail-Adresse eintragen</b>";
    } else {
        $statement = $pdo->prepare("SELECT * FROM users WHERE email = :email");
        $statement->execute(['email' => $_POST['email']]);
        $user = $statement->fetch();

        if($user === false) {
            $error = "<b>Kein Benutzer gefunden</b>";
        } else {
            $passwortcode = random_string();
            $statement = $pdo->prepare("UPDATE users SET passwortcode = :passwortcode, passwortcode_time = NOW() WHERE id = :userid");
            $statement->execute(['passwortcode' => sha1($passwortcode), 'userid' => $user['id']]);

            $empfaenger = $user['email'];
            $betreff = "Neues Passwort für deinen Account";
            $from = "From: DeinName <absender@domain.de>";
            $url_passwortcode = 'http://localhost/passwortzuruecksetzen.php?userid='.$user['id'].'&code='.$passwortcode;
            $text = 'Hallo '.$user['vorname'].',
            
            Um dein Passwort zurückzusetzen, klicke bitte auf folgenden Link:
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
<form action="?send=1" method="post">
E-Mail:<br>
<input type="email" name="email"><br>
<input type="submit" value="Neues Passwort anfordern">
</form>

<?php endif; ?>
```

#### 3. **Neues Passwort vergeben Seite (passwortzuruecksetzen.php)**

Wenn der Benutzer den Link in der E-Mail anklickt, wird er zu dieser Seite weitergeleitet, um ein neues Passwort festzulegen.

```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'passwort');

if(!isset

($_GET['userid'], $_GET['code'])) {
    die("Ungültiger Link");
}

$userid = $_GET['userid'];
$code = $_GET['code'];

$statement = $pdo->prepare("SELECT * FROM users WHERE id = :userid");
$statement->execute(['userid' => $userid]);
$user = $statement->fetch();

if($user === false || sha1($code) !== $user['passwortcode']) {
    die("Ungültiger Link");
}

$timeDiff = time() - strtotime($user['passwortcode_time']);
if($timeDiff > 86400) { // 24 Stunden
    die("Der Link ist abgelaufen.");
}

if(isset($_POST['passwort'])) {
    $newPassword = $_POST['passwort'];
    $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);

    $statement = $pdo->prepare("UPDATE users SET passwort = :passwort, passwortcode = NULL WHERE id = :userid");
    $statement->execute(['passwort' => $newPasswordHash, 'userid' => $userid]);

    echo "Passwort erfolgreich geändert!";
}
?>

<h1>Neues Passwort festlegen</h1>
<form action="" method="post">
Neues Passwort:<br>
<input type="password" name="passwort"><br>
<input type="submit" value="Passwort ändern">
</form>
```

---

### **6. "Angemeldet bleiben"-Feature**

Um ein „Angemeldet bleiben“-Feature hinzuzufügen, müssen wir Cookies verwenden. Wenn der Benutzer das Kontrollkästchen aktiviert, setzen wir ein Cookie für die Login-Informationen, das beim nächsten Besuch überprüft wird.

**Modifizierter Login-Teil**:

```php
if(isset($_POST['angemeldet_bleiben'])) {
    setcookie("userid", $user['id'], time() + 3600 * 24 * 30, "/"); // 30 Tage
}
```

**Login-Überprüfung bei jedem Seitenaufruf**:

```php
if(isset($_COOKIE['userid'])) {
    $_SESSION['userid'] = $_COOKIE['userid'];
}
```

---

### Fazit

In diesem Tutorial haben wir ein sicheres Login-System mit PHP und MySQL erstellt und zusätzlich das "Angemeldet bleiben"-Feature und Passwort-Wiederherstellung integriert. Dieses System ist flexibel und lässt sich leicht erweitern.
