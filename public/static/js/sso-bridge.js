/* Optional SSO browser bridge; credentials remain in HttpOnly cookies. */
(()=>{'use strict';
 let signingOut=false,redirecting=false;
 const expired=status=>{if(status===401&&!signingOut&&!redirecting){redirecting=true;location.assign('/login');}};
 const csrf=()=>{const p=document.cookie.split(';').map(s=>s.trim()).filter(s=>s.startsWith('__Host-chitanda_dns_csrf='));return p.length===1?p[0].slice(p[0].indexOf('=')+1):'';};
 const unsafe=m=>!['GET','HEAD','OPTIONS'].includes(String(m||'GET').toUpperCase());
 const open=XMLHttpRequest.prototype.open,send=XMLHttpRequest.prototype.send;
 XMLHttpRequest.prototype.open=function(method,url,...rest){this.ssoLocal=new URL(url,location.href).origin===location.origin;this.ssoWrite=this.ssoLocal&&unsafe(method);return open.call(this,method,url,...rest);};
 XMLHttpRequest.prototype.send=function(...args){if(this.ssoWrite)this.setRequestHeader('X-CSRF-Token',csrf());if(this.ssoLocal)this.addEventListener('loadend',()=>expired(this.status),{once:true});return send.apply(this,args);};
 const originalFetch=window.fetch;
 window.fetch=function(input,init={}){const request=new Request(input instanceof Request?input:new URL(input,location.href),init),local=new URL(request.url).origin===location.origin;if(local&&unsafe(request.method)){request.headers.set('X-CSRF-Token',csrf());}return originalFetch.call(this,request).then(response=>{if(local)expired(response.status);return response;});};
 document.addEventListener('submit',event=>{const form=event.target;if(form instanceof HTMLFormElement&&new URL(form.action,location.href).origin===location.origin&&unsafe(form.method)){if(new URL(form.action).pathname==='/logout')signingOut=true;let f=form.querySelector('input[name="_sso_csrf"]');if(!f){f=document.createElement('input');f.type='hidden';f.name='_sso_csrf';form.append(f);}f.value=csrf();}},true);
})();
