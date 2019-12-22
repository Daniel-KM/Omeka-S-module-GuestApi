Guest Api (module for Omeka S)
===================================

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

Four specific paths are added:

- /api/login
  The user can login with `/api/login?email=elisabeth.ii@example.com&password=***`.
  In return, a session token will be returned. All other actions can be done
  with them: `/api/users/me?key_identity=xxx&key_credential=yyy`.

- /api/logout

- /api/session-token
  A session token can be created for api access. It is reset each login or
  logout. The api keys has no limited life in Omeka.

- /api/register
  A visitor can register too, if allowed in the config. Register requires an
  email. Other params are optional: `username`, `password`, and `site` (id or
  slug, that may be required via the config).

In all other cases, use the standard api (/api/users/#id).

**Important**: For security, only guest users can use these methods currently.

**Warning**: The paths above may be changed in a future version to be more restful.


TODO
----

- Enable login via third parties.
- Normalize all api routes for restapi (register, login, logout, session-token).


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

* Copyright Daniel Berthereau, 2019 (see [Daniel-KM] on GitHub)


[Guest Api]: https://github.com/Daniel-KM/Omeka-S-module-GuestApi
[Guest]: https://github.com/Daniel-KM/Omeka-S-module-Guest
[Omeka S]: https://www.omeka.org/s
[Installing a module]: http://dev.omeka.org/docs/s/user-manual/modules/#installing-modules
[module issues]: https://github.com/Daniel-KM/Omeka-S-module-GuestApi/issues
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: http://opensource.org
[Daniel-KM]: https://github.com/Daniel-KM "Daniel Berthereau"
