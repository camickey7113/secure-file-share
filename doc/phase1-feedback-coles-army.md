# CS 1653 Project: Phase 1 Feedback

__Group:__ Coles Army

__Names:__ Kaul, Anita; Martin, Gabrielle J; Mickey, Cameron A; Swierczek, Cole J

__Users:__ ank249; gjm55; cam597; cjs309

## Comments

### Group information

Good organization.

Since you mentioned web experience, i'll assume your interface is web-based. In
that case, you may consider creating a client helper that runs on the provided
servers and interacts with the user-specified authentication server and resource
server. That is, since the AS and RS don't talk directly to one another, neither
one can play the role of the **web server** which provides the code for the
front-end and pulls in resources from the other. You could consider splitting
the "client" into two components: The javascript-based front-end that runs in
the browser, and a "coordination server" (or something) that provides the
front-end code and coordinates communication with the AS and RS, simulating a
more native application. Another option could be to make the client application
fully local (e.g., making it a browser extension or Electron app), so no server
has to deliver the client code. In this case, since the web front-end will
communicate directly with the AS and RS, you will need to implement cryptography
in the web browser, which may be an additional challenge. Either option may
require you to use SSH tunneling
(https://linuxconfig.org/introduction-to-ssh-port-forwarding) to enable your
local browser to communicate with the servers that we will make available.

Since you mentioned databases, i will suggest that you consider something like
SQLite rather than attempting to configure a database server on the provided
infrastructure. It's not required but i think it will save a lot of irrelevant
work.

10 / 10

### Design Proposal

Extremely little detail. What type of resource is stored? Why would users be
able to execute files on the server? What is stored about users, and how is it
used?

No notion of groups (or other metadata) as requested. How is it determined which
users can access what? Does everyone get everything? Please review the
instructions. This needs a lot of work before you can start implementing. I have
no issue with file sharing as the basis, but your description does not satisfy
the requirements.

30 / 45

### Security Properties

Good range of security properties, though some are vague. For instance, 3 says
that users can only perform authorized actions; what's considered an authorized
action? How would one determine whether this is upheld, given this information?

Some of your properties are implementation-level, describing more mechanism than
property. For instance, encryption of data isn't a security property, it's
instead a way for you to *achieve* a particular property. (In this case,
encryption of data would achieve the property that an attacker who gains
physical access will not be able to access file contents.)

45 / 45

## Overall

Minor: Please double check your formatting. The references section is not
readable, and should include full references rather than just URLs.

Your group organization and properties are good, but the project design is very
incomplete.

85 / 100

