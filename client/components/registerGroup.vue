<template>
  <div v-if="!isEmail" class="flex justify-center">
    <div class="flex" style="flex-direction: column; gap: 8px; width: 192px;">
      <twitchConnectButton />
      <youtubeConnectButton />
      <UButton block :ui="{ rounded: 'rounded-full' }" class="flex justify-center" label="Email or Username"
        icon="i-mdi-email-outline" color="gray" @click="isEmail = !isEmail">
      </UButton>
    </div>
  </div>
  <div v-else>
    <div class="flex justify-end" style="margin-bottom: 4px;">
      <UButton @click="isEmail = !isEmail" size="sm" color="primary" square variant="soft">
        <UIcon name="mdi:close" dynamic />
      </UButton>
    </div>
    <RegisterForm />
  </div>
</template>

<script lang="ts" setup>
const isEmail = ref(false)
</script>

<style></style>