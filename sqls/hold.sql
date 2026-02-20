create table indexing
(
    id                integer
        constraint indexing_pk
            primary key autoincrement,
    source            text    not null,
    destination       text    not null,
    sender            text    not null,
    recipient         text    not null,
    uploaded          int     not null,
    expire            integer not null,
    checksum          text    not null,
    tmp_filename      text    not null,
    original_filename text    not null,
    file_size         integer not null,
    file_type         text    not null
);

