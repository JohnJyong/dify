import logging
from datetime import datetime
from typing import Optional

import flask_login
from flask import request, redirect, current_app, session
from flask_restful import Resource

from libs.oauth import OAuthUserInfo, CMBCOAuth
from extensions.ext_database import db
from models.account import Account, AccountStatus
from services.account_service import AccountService, RegisterService
from .. import api


def get_oauth_providers():
    with current_app.app_context():
        cmbc_oauth = CMBCOAuth(
                               redirect_uri=current_app.config.get(
                                   'CONSOLE_URL') + '/console/api/oauth/authorize/cmbc')

        OAUTH_PROVIDERS = {
            'cmbc': cmbc_oauth
        }
        return OAUTH_PROVIDERS


class OAuthLogin(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
            print(vars(oauth_provider))
        if not oauth_provider:
            return {'error': 'Invalid provider'}, 400

        auth_url = oauth_provider.get_authorization_url()
        return redirect(auth_url)


class OAuthCallback(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {'error': 'Invalid provider'}, 400

        user_id = request.args.get('userId')

        account = _generate_account(provider, user_id)
        # Check account status
        if account.status == AccountStatus.BANNED.value or account.status == AccountStatus.CLOSED.value:
            return {'error': 'Account is banned or closed.'}, 403

        if account.status == AccountStatus.PENDING.value:
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = datetime.utcnow()
            db.session.commit()

        # login user
        session.clear()
        flask_login.login_user(account, remember=True)
        AccountService.update_last_login(account, request)

        return redirect(f'{current_app.config.get("CONSOLE_URL")}?oauth_login=success')


def _get_account_by_openid_or_email(provider: str, user_info: OAuthUserInfo) -> Optional[Account]:
    account = Account.get_by_openid(provider, user_info.id)

    if not account:
        account = Account.query.filter_by(email=user_info.email).first()

    return account


def _get_account_by_cmbc_user_id(provider: str, user_id: str) -> Optional[Account]:
    account = Account.get_by_openid(provider, user_id)

    if not account:
        account = Account.query.filter_by(email=user_id).first()

    return account


def _generate_account(provider: str, user_id: str):
    # Get account by openid or email.
    account = _get_account_by_cmbc_user_id(provider, user_id)

    if not account:
        # Create account
        account = RegisterService.register(
            email=user_id,
            name=user_id,
            password=None,
            open_id=user_id,
            provider=provider
        )

        # Set interface language
        preferred_lang = request.accept_languages.best_match(['zh', 'en'])
        if preferred_lang == 'zh':
            interface_language = 'zh-Hans'
        else:
            interface_language = 'en-US'
        account.interface_language = interface_language
        db.session.commit()

    # Link account
    AccountService.link_account_integrate(provider, user_id, account)

    return account


api.add_resource(OAuthLogin, '/oauth/login/<provider>')
api.add_resource(OAuthCallback, '/oauth/authorize/<provider>')
