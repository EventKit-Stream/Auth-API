<template>
  <UForm :validate="validate" :state="state" class="space-y-4" @submit="onSubmit">
    <UFormGroup label="Email" name="email">
      <UInput v-model="state.email" placeholder="Email address or Username" />
    </UFormGroup>
    <UFormGroup label="Password" name="password">
      <template #help>
        <div class="flex justify-end">
          <UButton variant="link" color="white" to="/authorize/forgot-password">Forgot Password?</UButton>
        </div>
      </template>
      <template #default>
        <UInput v-if="isPwdVisible" v-model="state.password" placeholder="Password" type="text"
          :ui="{ icon: { trailing: { pointer: '' } } }">
          <template #trailing>
            <UTooltip text="Hide Password">
              <UButton @click="isPwdVisible = !isPwdVisible" size="sm" color="primary" square
                :ui="{ rounded: 'rounded-full' }">
                <UIcon name="mdi:eye-outline" dynamic />
              </UButton>
            </UTooltip>
          </template>
        </UInput>
        <UInput v-else v-model="state.password" placeholder="Password" type="password"
          :ui="{ icon: { trailing: { pointer: '' } } }">
          <template #trailing>
            <UTooltip text="Show Password">
              <UButton @click="isPwdVisible = !isPwdVisible" size="sm" color="primary" square variant="soft"
                :ui="{ rounded: 'rounded-full' }">
                <UIcon name="mdi:eye-off-outline" dynamic />
              </UButton>
            </UTooltip>
          </template>
        </UInput>
      </template>
    </UFormGroup>
    <div class="flex justify-end">
      <UButton type="submit" :loading="isLoading" :disabled="validate(state).length > 0">
        Log In
      </UButton>
    </div>
  </UForm>
</template>

<script lang="ts" setup>
import type { FormError, FormSubmitEvent } from '#ui/types'

const isPwdVisible = ref(false)
const isLoading = ref(false)
const api_url = ref('')
const state = reactive({
  email: undefined,
  password: undefined,
})

const validate = (state: any): FormError[] => {
  const errors = []
  if (!state.email) {
    errors.push({ path: 'email', message: 'Required' })
  }
  if (!state.password) {
    errors.push({ path: 'password', message: 'Required' })
  }
  return errors
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

async function onSubmit(event: FormSubmitEvent<any>) {
  // Do something with data
  isLoading.value = true

  const formData = new URLSearchParams();
  formData.append("username", event.data.email);
  formData.append("password", event.data.password);
  formData.append("grant_type", "");
  formData.append("scope", "");
  formData.append("client_id", "");
  formData.append("client_secret", "");

  await getApiUrl()
  const loginEndpoint = `${api_url.value}/local/login`;
  fetch(loginEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.access_token) {
        const currentUri = new URL(window.location.href);
        const redirectUri = currentUri.searchParams.get("redirect_uri");
        const stateParam = currentUri.searchParams.get("state");
        window.localStorage.setItem("token", data.access_token);
        if (redirectUri) {
          window.location.href = `${redirectUri}?token_type=${data.token_type}&access_token=${data.access_token}&state=${stateParam}`;
          return;
        }
        window.location.href = `https://eventkit.stream/landing?token_type=${data.token_type}&access_token=${data.access_token}`;
      } else {
        isLoading.value = false;
        alert("Login Failed: " + data.detail);
      }
    })
    .catch((error) => {
      isLoading.value = false;
      console.error("Error:", error);
    });
}
</script>

<style></style>