
# Sécuriser l'interface d'administration 

Comment sécuriser l'interface d'administration d'un projet Symfony.

## Les différentes étapes 

1. **Créer une entité User**
```
$ symfony console make:user Admin
```
L'entité est appelée Admin

![Image résultat commande make:user](/assets/images/command-make-auth.png)

Cela ajoute une entité Admin dans le dossier */Entity*.

Cela met également à jour le fichier *security.yaml* dans *config/packages/*

![Image du fichier security.yaml](/assets/images/security-file.png)

2. **Mise à jour de la base de données**
```
$ symfony console make:migration
```
```
$ symfony console doctrine:migrations:migrate
```

3. **Créer un admin en base de données**
A créer manuellement ou en ligne de commande. Pensez à hasher le mot de passe.

Site internet permettant de hasher du texte : <https://www.bcrypt.fr/>

Exemple en ligne de commande avec admin en username et admin en password:
```sql
INSERT INTO `admin` (`id`, `username`, `roles`, `password`) VALUES (NULL, 'admin', '[\"ROLE_ADMIN\"]', '$2y$10$Ks7/O0VMoKPWd/C0P65anev1ZgwybEqJro2PvZ/UflgJXEfnud.FO');
```

4. **Créer le système d’authentification**
```
$ symfony console make:auth
```

![Image résultat de la commande make:auth](/assets/images/command-make-auth.png)

Cela met à jour le fichier *security.yaml*

```yaml
security:
    # https://symfony.com/doc/current/security.html#registering-the-user-hashing-passwords
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
    # https://symfony.com/doc/current/security.html#loading-the-user-the-user-provider
    providers:
        # used to reload user from session & other features (e.g. switch_user)
        app_user_provider:
            entity:
                class: App\Entity\Admin
                property: username
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
            custom_authenticator: App\Security\AppAuthenticator
            logout:
                path: app_logout
```

Cela crée un dossier *Security* dans *src* avec le AppAuthenticator. 


Cela crée également un template *login.html* dans *template/security*

5. **Configurer *AppAuthenticator.php***
Pour rediriger vers la route */admin* lors du succès de l’authentification.
```php
// ...
class AppAuthenticator extends AbstractLoginFormAuthenticator
{
    // ...

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('admin'));
    }

    // ...
}
```

6. **Configurer le contrôle d’accès aux routes**
Il faut configurer le contrôle d’accès dans *config/packages/security.yaml*, pour ne rendre la route admin accessible uniquement au rôle ADMIN.
```yaml
security:
    # ...
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        # - { path: ^/profile, roles: ROLE_USER }
```

7. **Mettre en forme le template du formulaire de login**
Lorsque l'on se rend sur l'url /admin on tombe sur le formulaire de login.

## Documentation Symfony

- <https://symfony.com/doc/current/security.html#the-user>
- <https://symfony.com/doc/current/the-fast-track/fr/15-security.html>