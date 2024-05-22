<script lang="ts" setup>
import type { FormError, FormSubmitEvent } from '#ui/types'
const isPwdVisible = ref(false)
const isConfPwdVisible = ref(false)
const isLoading = ref(false)
const api_url = ref('')
const state = reactive({
  username: undefined,
  email: undefined,
  password: undefined,
  ConfPassword: undefined,
})
const minPasswordLength = 8
const minUppercaseChars = 1
const minLowercasedChars = 1
const minDigits = 1
const minSpecialChars = 1

const validate = (state: any): FormError[] => {
  const errors = []
  if (!state.username) {
    errors.push({ path: 'username', message: 'Required' })
  }
  if (!state.email) {
    errors.push({ path: 'email', message: 'Required' })
  }
  if (!state.password) {
    errors.push({ path: 'password', message: 'Required' })
  } else {
    if (state.password.length < minPasswordLength) {
      errors.push({ path: 'password', message: `Must be at least ${minPasswordLength} characters` })
    }
    if (!/[A-Z]/.test(state.password)) {
      errors.push({ path: 'password', message: `Must contain at least ${minUppercaseChars} uppercase letter` })
    }
    if (!/[a-z]/.test(state.password)) {
      errors.push({ path: 'password', message: `Must contain at least ${minLowercasedChars} lowercase letter` })
    }
    if (!/\d/.test(state.password)) {
      errors.push({ path: 'password', message: `Must contain at least ${minDigits} digit` })
    }
    if (!/[^a-zA-Z0-9]/.test(state.password)) {
      errors.push({ path: 'password', message: `Must contain at least ${minSpecialChars} special character` })
    }
  }

  if (!state.ConfPassword) {
    errors.push({ path: 'ConfPassword', message: 'Required' })
  } else {
    if (state.ConfPassword !== state.password) {
      errors.push({ path: 'ConfPassword', message: 'Passwords do not match' })
    }
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
  const url_params = new URLSearchParams(window.location.search);
  const token = url_params.get('token');

  await getApiUrl()
  const requestUri = `${api_url.value}/local/reset-password`;

  const formData = new URLSearchParams();
  if (token && state.username && state.email && state.password && state.ConfPassword) {
    formData.append("token", token);
    formData.append("username", state.username);
    formData.append("email", state.email);
    formData.append("new_password", state.password);
    formData.append("confirm_password", state.ConfPassword);
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
        <h1 class="text-2xl font-semibold">Event Kit - Reset Password</h1>
      </template>
      <UForm class="space-y-4" :validate="validate" :state="state" @submit="onSubmit">
        <UFormGroup label="Username" name="username">
          <template #default>
            <UInput v-model="state.username" placeholder="Username" />
          </template>
        </UFormGroup>
        <UFormGroup label="Email" name="email">
          <template #default>
            <UInput v-model="state.email" placeholder="Email address" />
          </template>
        </UFormGroup>
        <UFormGroup label="Password" name="password">
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
        </UFormGroup>
        <UFormGroup label="Confirm Password" name="ConfPassword">
          <UInput v-if="isConfPwdVisible" v-model="state.ConfPassword" placeholder="Password" type="text"
            :ui="{ icon: { trailing: { pointer: '' } } }">
            <template #trailing>
              <UTooltip text="Hide Password">
                <UButton @click="isConfPwdVisible = !isConfPwdVisible" size="sm" color="primary" square
                  :ui="{ rounded: 'rounded-full' }">
                  <UIcon name="mdi:eye-outline" dynamic />
                </UButton>
              </UTooltip>
            </template>
          </UInput>
          <UInput v-else v-model="state.ConfPassword" placeholder="Password" type="password"
            :ui="{ icon: { trailing: { pointer: '' } } }">
            <template #trailing>
              <UTooltip text="Show Password">
                <UButton @click="isConfPwdVisible = !isConfPwdVisible" size="sm" color="primary" square variant="soft"
                  :ui="{ rounded: 'rounded-full' }">
                  <UIcon name="mdi:eye-off-outline" dynamic />
                </UButton>
              </UTooltip>
            </template>
          </UInput>
        </UFormGroup>
        <div class="flex justify-end" style="margin-top: 16px;">
          <UButton type="submit" :loading="isLoading" :disabled="validate(state).length > 0">
            Send Reset Link
          </UButton>
        </div>
      </UForm>
    </UCard>
  </div>
</template>

<style></style>