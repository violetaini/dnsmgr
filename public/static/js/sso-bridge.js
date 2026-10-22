/* Optional SSO browser bridge; credentials remain in HttpOnly cookies. */
(()=>{'use strict';
 const csrf=()=>{const p=document.cookie.split(';').map(s=>s.trim()).filter(s=>s.startsWith('__Host-chitanda_dns_csrf='));return p.length===1?p[0].slice(p[0].indexOf('=')+1):'';};
 const unsafe=m=>!['GET','HEAD','OPTIONS'].includes(String(m||'GET').toUpperCase());
 const open=XMLHttpRequest.prototype.open,send=XMLHttpRequest.prototype.send;
 XMLHttpRequest.prototype.open=function(method,url,...rest){this.ssoWrite=new URL(url,location.href).origin===location.origin&&unsafe(method);return open.call(this,method,url,...rest);};
 XMLHttpRequest.prototype.send=function(...args){if(this.ssoWrite)this.setRequestHeader('X-CSRF-Token',csrf());return send.apply(this,args);};
 const originalFetch=window.fetch;
 window.fetch=function(input,init={}){const request=new Request(input instanceof Request?input:new URL(input,location.href),init);if(new URL(request.url).origin===location.origin&&unsafe(request.method)){request.headers.set('X-CSRF-Token',csrf());}return originalFetch.call(this,request);};
 document.addEventListener('submit',event=>{const form=event.target;if(form instanceof HTMLFormElement&&new URL(form.action,location.href).origin===location.origin&&unsafe(form.method)){let f=form.querySelector('input[name="_sso_csrf"]');if(!f){f=document.createElement('input');f.type='hidden';f.name='_sso_csrf';form.append(f);}f.value=csrf();}},true);
 document.addEventListener('DOMContentLoaded',()=>{for(const a of document.querySelectorAll('a[href="/setpwd"]')){a.href='/sso/account';a.innerHTML='<i class="fa fa-user"></i> 账号中心';}});
})();
