<template>
  <UButton block :ui="{ rounded: 'rounded-full' }" class="flex justify-center" label="YouTube" color="youtube"
    icon="i-mdi-youtube" @click="googleConnect()">
  </UButton>
</template>

<script lang="ts" setup>
const api_url = ref('')

function genRanHex(arg0: number) {
  const hexChars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < arg0; i++) {
    const randomIndex = Math.floor(Math.random() * hexChars.length);
    result += hexChars[randomIndex];
  }
  return result;
}

async function getApiUrl() {
  const url = new URL(window.location.href);
  const origin = url.origin;
  try {
    const response = await fetch(`${origin}/api_str`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    const data = await response.json();
    api_url.value = origin + data.api_str;
  } catch (error) {
    console.error('Error:', error);
  }
}

async function googleConnect() {
  const googleEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
  const client_id = "863823633798-pf0lprdq3u28aempaqn0nvea8vt1q3vh.apps.googleusercontent.com";
  await getApiUrl()
  const redirect_uri = `${api_url.value}/google/callback`;
  const response_type = "code";
  const scope = "openid profile email";// https://www.googleapis.com/auth/youtube.readonly";
  const access_type = "offline";
  const state_val = genRanHex(32);;
  const include_granted_scopes = "true";
  const nonce_val = genRanHex(32);;
  const googleUrl = `${googleEndpoint}?scope=${encodeURIComponent(scope)}&access_type=${access_type}&include_granted_scopes=${include_granted_scopes}&state=${state_val}&nonce=${nonce_val}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=${response_type}&client_id=${client_id}`;

  window.localStorage.setItem('state', state_val);
  window.localStorage.setItem('nonce', nonce_val);

  await navigateTo(googleUrl, {
    external: true
  });
}
</script>

<style></style>