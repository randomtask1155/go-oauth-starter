# go oauth starter kit

Basic implementation for google Oauth handler to obtain a users google profile access token

### Backend Requirements

 * Database table "users"

```
CREATE TABLE users (
	id serial,
	username varchar(255),
	refreshtoken varchar(4096)
);
```

### Build instructions

Setup env.sh or manifest.yml ( cloud foundry ) with proper environmental variables

```godep go install```
