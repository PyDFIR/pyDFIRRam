# from pydfirram import __version__


# def test_version():
#     assert __version__ == '0.2.0'

def test_generic():
    from pydfirram.core.base import Generic, OperatingSystem
    os = OperatingSystem.WINDOWS

    generic = Generic(os)

    assert str(generic) == "Generic OS: WINDOWS"
    assert generic.get_plugins_list() == []
