<template>
  <UButton block :ui="{ rounded: 'rounded-full' }" class="flex justify-center" label="Twitch" color="twitch"
    icon="i-mdi-twitch" @click="twitchConnect()">
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

async function twitchConnect() {
  const twitchEndpoint = "https://id.twitch.tv/oauth2/authorize";
  const response_type = "code";
  const client_id = "5znc2kui2tzjj6dpdhqiitayqz1ju4";
  const scope = "user:read:email+openid";
  const state_val = genRanHex(32);;
  const nonce_val = genRanHex(32);;

  await getApiUrl()
  const redirect_uri = `${api_url.value}/twitch/callback`;
  const claims = { "id_token": { "email": null, "preferred_username": null, "email_verified": null }, "userinfo": { "email": null, "email_verified": null, "picture": null, "preferred_username": null, "updated_at": null } }
  const str_claims = JSON.stringify(claims);
  const twitchUrl = `${twitchEndpoint}?response_type=${encodeURIComponent(response_type)}&client_id=${encodeURIComponent(client_id)}&scope=${scope}&state=${encodeURIComponent(state_val)}&redirect_uri=${encodeURIComponent(redirect_uri)}&nonce=${encodeURIComponent(nonce_val)}&claims=${str_claims}`;

  window.localStorage.setItem('state', state_val);
  window.localStorage.setItem('nonce', nonce_val);

  await navigateTo(twitchUrl, {
    external: true
  });
}
</script>

<style></style>