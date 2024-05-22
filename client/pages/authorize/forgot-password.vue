<script lang="ts" setup>
import type { FormError, FormSubmitEvent } from '#ui/types'
const api_url = ref('')

const state = reactive({
  username: undefined,
  email: undefined,
})
const isLoading = ref(false)
const isRequestSent = ref(false)

const validate = (state: any): FormError[] => {
  const errors = []
  if (!state.username) {
    errors.push({ path: 'username', message: 'Required' })
  }
  if (!state.email) {
    errors.push({ path: 'email', message: 'Required' })
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
  isLoading.value = true

  await getApiUrl()
  const requestUri = `${api_url.value}/local/recover-password`;

  const formData = new URLSearchParams();
  if (state.username && state.email) {
    formData.append("username", state.username);
    formData.append("email", state.email);
  } else {
    isLoading.value = false;
    alert("Please fill in all fields");
  }
  fetch(requestUri, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.message) {
        isLoading.value = false;
        isRequestSent.value = true;
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

<template>
  <div class="flex justify-center" style="height: 100vh; align-items: center;">
    <UCard style="width: 512px; height: fit-content;">
      <template #header>
        <h1 class="text-2xl font-semibold">Event Kit - Forgot Password</h1>
      </template>
      <UForm class="space-y-4" :validate="validate" :state="state" @submit="onSubmit">
        <UFormGroup label="Username" name="username">
          <UInput v-model="state.email" placeholder="Username" type="text" />
        </UFormGroup>
        <UFormGroup label="Email" name="email">
          <UInput v-model="state.email" placeholder="Email" type="email" />
        </UFormGroup>
        <div class="flex justify-end">
          <UButton type="submit" :loading="isLoading" :disabled="validate(state).length > 0">
            Send Reset Link
          </UButton>
        </div>
      </UForm>
      <UAlert v-if="isRequestSent" icon="i-mdi-lock-reset" color="primary" variant="subtle" title="Notification Sent!"
        description="Please check your email for the reset link.">
        AAA
      </UAlert>
    </UCard>
  </div>
</template>

<style></style>