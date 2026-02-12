"""
NetRunner OS - Address Book Routes
"""

from flask import Blueprint, request, jsonify
from app.core.addresses import list_addresses, add_address, delete_address

bp = Blueprint('addresses', __name__)


@bp.route('/addresses', methods=['GET'])
def get_all():
    return jsonify(list_addresses())


@bp.route('/addresses', methods=['POST'])
def create():
    data = request.get_json()
    if not data or not data.get('ip'):
        return jsonify({'error': 'IP address is required.'}), 400
    entry = add_address(
        name=data.get('name', ''),
        ip=data['ip'],
        mac=data.get('mac', '')
    )
    return jsonify(entry), 201


@bp.route('/addresses/<address_id>', methods=['DELETE'])
def delete(address_id):
    if delete_address(address_id):
        return jsonify({'status': 'Deleted.'})
    return jsonify({'error': 'Address not found.'}), 404
