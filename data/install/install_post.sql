INSERT INTO setting(id, value)
SELECT REPLACE(s.id, "guestuserapi_", "guestapi_"), value
FROM setting s
WHERE id LIKE "guestuserapi\_%"
ON DUPLICATE KEY UPDATE
    id = REPLACE(s.id, "guestuserapi_", "guestapi_"),
    value = s.value
;
DELETE FROM setting
WHERE id LIKE "guestuserapi\_%"
;
