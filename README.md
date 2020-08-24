Guest Api (module for Omeka S)
==============================


> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better.__

[Guest Api] is a module for [Omeka S] that allows to manage the actions of the
module [Guest] by an api, in particular to register and to update its own
profile.

The guest api does not replace the standard api (/api/users/#id), but add some
checks and features.


Installation
------------

Install module [Guest] first.

Uncompress files in the module directory and rename module folder `GuestApi`.
Then install it like any other Omeka module and follow the config instructions.

See general end user documentation for [Installing a module].


Usage
-----

First, specify the roles that can login by api in the config form of the module.
Note that to allow any roles to login, in particular global admins, increase the
access points to check for security.

To update the profile, use the path /api/users/me. For example to update:
- email: /api/users/me?email=elisabeth.ii@example.com
- name: /api/users/me?name=elisabeth_ii
- password: /api/users/me?password=xxx&new_password=yyy

In all other cases, you should use the standard api (`/api/users/#id`).

Four specific paths are added:

- /api/login
  The user can login with a post to `/api/login` with data `{"email":"elisabeth.ii@example.com","password"=""***"}`.
  In return, a session token will be returned. All other actions can be done
  with them: `/api/users/me?key_identity=xxx&key_credential=yyy`.

  If the option to create a local session cookie is set, the user will be
  authenticated locally too, so it allows to login from a third party webservice,
  for example if a user logs in inside a Drupal site, he can log in the Omeka
  site simultaneously. This third party log in should be done via an ajax call
  because the session cookie should be set in the browser, not in the server, so
  you can’t simply call the endpoint from the third party server. In you third
  party ajax, the header `Origin` should be filled in the request; this is
  generally the case with common js libraries.

  When a local session cookie is wanted, it is recommended to add a list of
  sites that have the right to log in the config for security reasons.

- /api/logout

- /api/session-token
  A session token can be created for api access. It is reset each login or
  logout. The api keys has no limited life in Omeka.

- /api/register
  A visitor can register too, if allowed in the config. Register requires an
  email. Other params are optional: `username`, `password`, and `site` (id or
  slug, that may be required via the config).

**Warning**: The paths above may be changed in a future version to be more restful.


TODO
----

- Normalize all api routes and json for rest api (register, login, logout, session-token).


Warning
-------

Use it at your own risk.

It’s always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page.


License
-------

This plugin is published under the [CeCILL v2.1] licence, compatible with
[GNU/GPL] and approved by [FSF] and [OSI].

In consideration of access to the source code and the rights to copy, modify and
redistribute granted by the license, users are provided only with a limited
warranty and the software’s author, the holder of the economic rights, and the
successive licensors only have limited liability.

In this respect, the risks associated with loading, using, modifying and/or
developing or reproducing the software by the user are brought to the user’s
attention, given its Free Software status, which may make it complicated to use,
with the result that its use is reserved for developers and experienced
professionals having in-depth computer knowledge. Users are therefore encouraged
to load and test the suitability of the software as regards their requirements
in conditions enabling the security of their systems and/or data to be ensured
and, more generally, to use and operate it in the same conditions of security.
This Agreement may be freely reproduced and published, provided it is not
altered, and that no provisions are either added or removed herefrom.


Copyright
---------

* Copyright Daniel Berthereau, 2019-2020 (see [Daniel-KM] on GitLab)


[Guest Api]: https://gitlab.com/Daniel-KM/Omeka-S-module-GuestApi
[Guest]: https://gitlab.com/Daniel-KM/Omeka-S-module-Guest
[Omeka S]: https://www.omeka.org/s
[GitLab]: https://gitlab.com/Daniel-KM/Omeka-S-module-GuestApi
[Installing a module]: http://dev.omeka.org/docs/s/user-manual/modules/#installing-modules
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-GuestApi/issues
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: http://opensource.org
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
