(() => {
  const fromB64u = (value) => {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(base64);
    return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
  };
  const toB64u = (buffer) => {
    const bytes = new Uint8Array(buffer || new ArrayBuffer(0));
    let binary = '';
    bytes.forEach(b => { binary += String.fromCharCode(b); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const creationOptions = (json) => {
    if (window.PublicKeyCredential?.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(json);
    return {
      ...json,
      challenge: fromB64u(json.challenge),
      user: {...json.user, id: fromB64u(json.user.id)},
      excludeCredentials: (json.excludeCredentials || []).map(c => ({...c, id: fromB64u(c.id)})),
    };
  };
  const requestOptions = (json) => {
    if (window.PublicKeyCredential?.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(json);
    return {
      ...json,
      challenge: fromB64u(json.challenge),
      allowCredentials: (json.allowCredentials || []).map(c => ({...c, id: fromB64u(c.id)})),
    };
  };
  const credentialToJSON = (credential) => {
    if (typeof credential.toJSON === 'function') return credential.toJSON();
    const response = credential.response;
    const result = {id: credential.id, type: credential.type, rawId: toB64u(credential.rawId), response: {clientDataJSON: toB64u(response.clientDataJSON)}};
    if (response.attestationObject) {
      result.response.attestationObject = toB64u(response.attestationObject);
      result.response.transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
    } else {
      result.response.authenticatorData = toB64u(response.authenticatorData);
      result.response.signature = toB64u(response.signature);
      result.response.userHandle = response.userHandle ? toB64u(response.userHandle) : null;
    }
    if (credential.authenticatorAttachment) result.authenticatorAttachment = credential.authenticatorAttachment;
    if (typeof credential.getClientExtensionResults === 'function') result.clientExtensionResults = credential.getClientExtensionResults();
    return result;
  };
  window.imWebAuthn = {creationOptions, requestOptions, credentialToJSON};
})();
