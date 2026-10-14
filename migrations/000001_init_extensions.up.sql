-- citext: case-insensitive text, used for unique emails.
CREATE EXTENSION IF NOT EXISTS citext;

-- btree_gist: lets a GiST exclusion constraint combine "=" on ids with "&&" on
-- time ranges, which guarantees that one slot cannot be booked twice.
CREATE EXTENSION IF NOT EXISTS btree_gist;
