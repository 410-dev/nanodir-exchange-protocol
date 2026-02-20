create table groups
(
    id              integer
        constraint groups_pk
            primary key autoincrement,
    network         text not null,
    group_full_path text not null,
    group_name      text not null,
    group_parent    text not null,
    group_uid       text not null
);


create table machines
(
    id              integer
        constraint machines_pk
            primary key autoincrement,
    type            text    not null,
    group_full_path integer not null,
    group_uid       integer not null,
    name            text    not null,
    owner           text    not null,
    policies        text    not null,
    totp            text    not null,
    enc_publickey   text    not null
);

create table users
(
    id                      integer
        constraint int
            primary key autoincrement,
    uid                     TEXT                not null,
    email                   text                not null,
    name                    text                not null,
    profilepic              text,
    max_devices             integer default 999 not null,
    reset_password_on_logon INT,
    password                text                not null,
    password_expire         integer,
    network                 text                not null,
    group_full_path         text                not null,
    group_uid               text                not null,
    totp                    text
);

