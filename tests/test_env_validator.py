from envshield.scanners.env_validator import infer_type, parse_env_file


def test_infer_type_empty():
    assert infer_type("") == "empty"

def test_infer_type_float():
    assert infer_type("1.5") == "float"
    
def test_parse_env_file_empty_line():
    content = "\n#comment\nPORT=80\n"
    res = parse_env_file(content)
    assert "PORT" in res
