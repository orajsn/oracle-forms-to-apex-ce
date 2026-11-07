"""Internal bearer-protected prototype handoff; caller supplies trusted gateway."""
import asyncio
import hmac
import hashlib
import json
import zipfile

from starlette.responses import JSONResponse, Response
from .security import validate_job_id


def attach_prototype_routes(mcp, gateway, settings):
    def authorized(request):
        return hmac.compare_digest(request.headers.get('authorization', '').encode(),
                                   ('Bearer ' + settings.bearer_token).encode())

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate field')
            result[key] = value
        return result

    async def body(request, limit):
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > limit:
                raise OverflowError()
            raw.extend(chunk)
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))

    @mcp.custom_route('/fox/prototype/capabilities', methods=['GET'], include_in_schema=False)
    async def capabilities(request):
        if not authorized(request):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
        stages = ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
        return JSONResponse({'schema_version': 1, 'scope': 'fox-prototype-capabilities-v1',
                             'stages': [stage for stage in stages if gateway.supports(stage)]})

    @mcp.custom_route('/fox/prototype/jobs/{job_id}/package', methods=['GET'], include_in_schema=False)
    async def package(request):
        if not authorized(request):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
        try:
            job_id = request.path_params['job_id']; validate_job_id(job_id)
            raw = await asyncio.to_thread(gateway.read_package, job_id)
            if raw is None:
                return JSONResponse({'error': 'Not found'}, status_code=404)
            return Response(raw, media_type='application/zip', headers={
                'Content-Disposition': f'attachment; filename="{job_id}-generated-prototype.zip"',
                'X-Content-SHA256': hashlib.sha256(raw).hexdigest(),
                'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
        except (ValueError, TypeError, RuntimeError, OSError, KeyError, zipfile.BadZipFile):
            return JSONResponse({'error': 'Generated prototype export is unavailable or could not be verified. Existing evidence is preserved.'}, status_code=409)

    @mcp.custom_route('/fox/prototype/jobs/{job_id}/authority', methods=['POST', 'GET'], include_in_schema=False)
    async def authority(request):
        if not authorized(request):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
        try:
            job_id = request.path_params['job_id']; validate_job_id(job_id)
            if request.method == 'POST':
                value = await body(request, 96 * 1024 * 1024)
                result = await asyncio.to_thread(gateway.stage_source_authority, job_id, value)
                return JSONResponse(result, status_code=201)
            result = await asyncio.to_thread(gateway.recover_source_authority, job_id)
            return JSONResponse(result) if result is not None else JSONResponse({'error': 'Not found'}, status_code=404)
        except OverflowError:
            return JSONResponse({'error': 'Authority package too large'}, status_code=413)
        except (ValueError, TypeError, RuntimeError, OSError, KeyError):
            return JSONResponse({'error': 'Prototype authority handoff could not be verified. Existing evidence is preserved.'}, status_code=409)

    @mcp.custom_route('/fox/prototype/jobs/{job_id}/stages/{stage}', methods=['POST', 'GET'], include_in_schema=False)
    async def stage(request):
        if not authorized(request):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
        try:
            job_id = request.path_params['job_id']; validate_job_id(job_id)
            stage_name = request.path_params['stage']
            if stage_name not in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export'):
                raise ValueError('Unknown stage')
            if request.method == 'POST':
                value = await body(request, 2_000_000)
                if not isinstance(value, dict) or value.get('job_id') != job_id:
                    raise ValueError('Job mismatch')
                result = await asyncio.to_thread(gateway.run_stage, stage_name, value)
            else:
                result = await asyncio.to_thread(gateway.recover_stage_for_job, job_id, stage_name)
            return JSONResponse(result) if result is not None else JSONResponse({'error': 'Not found'}, status_code=404)
        except OverflowError:
            return JSONResponse({'error': 'Stage request too large'}, status_code=413)
        except (ValueError, TypeError, RuntimeError, OSError, KeyError):
            return JSONResponse({'error': 'Prototype stage requires attention. Inspect retained evidence; do not replay an uncertain operation.'}, status_code=409)
