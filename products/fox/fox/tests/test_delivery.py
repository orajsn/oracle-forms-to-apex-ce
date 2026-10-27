from pathlib import Path
from fastapi.testclient import TestClient
from fox.app import create_app, password_hash

def test_static_delivery_and_private_api(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('test-only-password'))
    dist=Path(__file__).resolve().parents[1]/'dist'
    assert dist.exists(), 'Run npm run build before delivery tests'
    with TestClient(create_app(tmp_path,enable_worker=False)) as client:
        asset=next((dist/'assets').glob('*.js'))
        response=client.get('/assets/'+asset.name,headers={'Accept-Encoding':'gzip'})
        assert response.status_code==200
        assert response.headers['Content-Encoding']=='gzip'
        assert response.headers['Cache-Control']=='public, max-age=31536000, immutable'
        assert response.content==asset.read_bytes()
        assert client.get('/').headers['Cache-Control']=='no-cache'
        assert client.get('/api/session').headers['Cache-Control']=='no-store'
        assert 'immutable' not in client.get('/assets/missing-file.js').headers['Cache-Control']
