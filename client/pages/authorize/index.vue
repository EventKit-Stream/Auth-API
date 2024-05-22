<script lang="ts" setup>
// TODO: Create and use OgImageComponent
defineOgImageComponent('NuxtSeo', {
  //scolorMode: 'dark',
  title: "Event Kit",
  description: "This is the authentication website for Event Kit.",
  icon: "simple-icons:authelia",
  siteName: "id.EventKit.stream/authorize",
  //siteLogo: "/favicon.ico",
  theme: "151a6f"
})

definePageMeta({
  title: 'Authorization',

})

const items = [{
  slot: 'login',
  label: 'Log In'
}, {
  slot: 'register',
  label: 'Sign Up'
}]
</script>

<template>
  <div class="flex justify-center" style="height: 100vh; align-items: center;">
    <UCard style="width: 512px; height: fit-content;">
      <template #header>
        <h1 class="text-2xl font-semibold">Event Kit</h1>
      </template>
      <UTabs :items="items" :default-index="0" class="w-full">
        <template #login="{ item }">
          <loginGroup />
        </template>
        <template #register="{ item }">
          <registerGroup />
        </template>
      </UTabs>
    </UCard>
  </div>
</template>

<style></style>