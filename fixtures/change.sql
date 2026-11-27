-- db exec fixture: a governed change on exec_demo, the throwaway table the test creates in its own
-- schema (search_path of its own write role), so no shared fixture table is ever touched.
INSERT INTO exec_demo (note) VALUES ('first'), ('second');
UPDATE exec_demo SET note = 'first, edited' WHERE note = 'first';
DELETE FROM exec_demo WHERE note = 'second';
