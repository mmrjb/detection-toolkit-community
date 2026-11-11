from detection_toolkit.db import connect


def test_mitre_index_holds_only_tagged_techniques(app):
    with connect(app.config["DTK_DB_PATH"]) as conn:
        mapped = sorted(row[0] for row in conn.execute("SELECT technique FROM mitre_index"))
    assert mapped == ["T1003.001", "T1047", "T1053.005", "T1059.001", "T1105", "T1218.011", "T1547.001"]


def test_init_db_refuses_to_overwrite(app):
    import pytest
    from detection_toolkit.db import init_database
    with pytest.raises(FileExistsError):
        init_database(app.config)
