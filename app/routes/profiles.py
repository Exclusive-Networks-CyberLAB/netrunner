"""
NetRunner OS - Profile Management Routes
"""

from flask import Blueprint, request, jsonify
from app.core.profiles import (
    list_profiles, get_profile, save_profile,
    delete_profile, export_profile, import_profile
)

bp = Blueprint('profiles', __name__)


@bp.route('/profiles', methods=['GET'])
def list_all():
    return jsonify(list_profiles())


@bp.route('/profiles/<profile_id>', methods=['GET'])
def get_one(profile_id):
    profile = get_profile(profile_id)
    if not profile:
        return jsonify({'error': 'Profile not found.'}), 404
    return jsonify(profile)


@bp.route('/profiles', methods=['POST'])
def save():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided.'}), 400
    result = save_profile(data)
    return jsonify(result)


@bp.route('/profiles/<profile_id>', methods=['DELETE'])
def delete(profile_id):
    if delete_profile(profile_id):
        return jsonify({'status': 'Deleted.'})
    return jsonify({'error': 'Profile not found.'}), 404


@bp.route('/profiles/export/<profile_id>', methods=['GET'])
def export(profile_id):
    profile = export_profile(profile_id)
    if not profile:
        return jsonify({'error': 'Profile not found.'}), 404
    return jsonify(profile)


@bp.route('/profiles/import', methods=['POST'])
def import_prof():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided.'}), 400
    result = import_profile(data)
    return jsonify(result)
